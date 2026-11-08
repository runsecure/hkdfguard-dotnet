using System.Collections.Concurrent;
using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.SecureFile;

namespace HkdfGuard.KeyWrapping.AzureKeyVault;

/// <summary>
/// Protects (wraps) and reveals (unwraps) a DEK under an RSA key in Azure Key Vault, and signs every
/// wrapped DEK with a second, EC P-256 key in the vault. The private keys never enter this process;
/// unwrapping and signing are calls to Key Vault, authorized by the caller's Azure credential.
/// <para>
/// Why two keys: RSA-OAEP wrapping needs only the public key, which isn't secret, so without the
/// signature anyone could produce a wrapped DEK this wrapper would accept - holding a DEK they
/// chose, which the application would then encrypt new data under. Signing needs the signing key's
/// private half, held in Key Vault and usable only by principals granted <c>sign</c>. Unwrap checks
/// the signature before it unwraps anything, so a wrapped DEK proves it was made by a principal
/// allowed to sign: give that permission to the pipeline that creates key files, never to the
/// application. Each key does one job; the wrapper refuses the same key for both.
/// </para>
/// <para>
/// Both keys are pinned: a wrapped DEK records only the key versions it was made with (see
/// WrappedDekEnvelope), and the vault and key names always come from the constructor. Rotating
/// either key in Key Vault therefore needs nothing here - existing key files keep naming the
/// version that made them, which must stay enabled while they're in use. The wrapper keeps one
/// Key Vault client per key version, but only once a call through it succeeds, so a wrapped DEK
/// naming a version Key Vault refuses leaves nothing behind.
/// </para>
/// <para>
/// A kept client is replaced once it is <see cref="ClientLifetime"/> old (5 minutes unless
/// configured otherwise). The Azure SDK verifies a signature in this process, with a public key it
/// fetched once and never checks again, so a client kept for good would go on accepting key files
/// signed under a version you have since disabled or purged - after a signing identity is
/// compromised, exactly the files you are trying to refuse. A fresh client asks Key Vault again, so
/// disabling or purging a signing key version stops a running process accepting it within one
/// lifetime. The cost is one key read per key version per lifetime.
/// </para>
/// <para>
/// The optional context is bound into the signature, and must be given again, exactly, to reveal
/// the DEK: a key file made for one application can't be used by another that shares the keys.
/// Key Vault has no "generate data key", so <see cref="GenerateAndWrapAsync"/> generates the DEK in
/// this process, wraps it, and zeroes it. Plaintext key bytes this class owns are zeroed once used;
/// the Azure SDK's own copies (request bodies, the unwrap response) can't be, and live until
/// collected.
/// </para>
/// </summary>
public sealed class AzureKeyVaultKeyWrapper : IKeyWrapper
{
    /// <summary>The length of the DEK <see cref="GenerateAndWrapAsync"/> generates: 32 bytes (AES-256).</summary>
    public const int GeneratedKeyLength = 32;

    /// <summary>The largest plaintext RSA-OAEP-256 wraps under a 2048-bit key, in bytes.</summary>
    public const int MaxPlaintextLength = 190;

    /// <summary>How long a Key Vault client is kept for a key version, unless configured otherwise: 5 minutes.</summary>
    public static readonly TimeSpan DefaultClientLifetime = TimeSpan.FromMinutes(5);

    /// <summary>The longest <see cref="ClientLifetime"/> accepted: 1 hour.</summary>
    public static readonly TimeSpan MaxClientLifetime = TimeSpan.FromHours(1);

    private readonly KeyVaultKeyIdentifier _wrappingKey;
    private readonly KeyVaultKeyIdentifier _signingKey;
    private readonly Uri _wrappingKeyId;
    private readonly Uri _signingKeyId;
    private readonly Func<Uri, CryptographyClient> _clientFactory;
    // Each kept client with the TimeProvider timestamp it was created at.
    private readonly ConcurrentDictionary<Uri, (CryptographyClient Client, long CreatedAt)> _clients = new();
    private readonly TimeProvider _timeProvider;
    private readonly byte[] _context;
    private readonly KeyFileTrust _keyFileTrust;

    /// <param name="wrappingKeyId">The RSA key that wraps every DEK (2048 or 3072 bits), as its key
    /// identifier: https://{vault}.vault.azure.net/keys/{name}, optionally with a version to wrap
    /// under that version rather than the current one.</param>
    /// <param name="signingKeyId">The EC P-256 key that signs every wrapped DEK, in the same form.</param>
    /// <param name="credential">Authenticates every call to Key Vault, e.g. a managed identity.</param>
    /// <param name="context">Bound into every wrapped DEK's signature and required again to reveal
    /// it; null binds none. Not secret.</param>
    /// <param name="keyFileTrust">Who besides the operating system's administrators may have
    /// written a key file <see cref="ReadKeyFileAsync"/> reads; null trusts administrators only.</param>
    /// <param name="options">Options for the Key Vault clients; null for the defaults.</param>
    /// <param name="clientLifetime">How long a Key Vault client is kept for a key version before a
    /// fresh one replaces it, which bounds how long a disabled or purged signing key version keeps
    /// verifying in a running process; null for <see cref="DefaultClientLifetime"/>.</param>
    /// <exception cref="ArgumentNullException">A key identifier or the credential is null</exception>
    /// <exception cref="ArgumentException">A key identifier isn't a Key Vault key's, both name the
    /// same key, or the context is too long</exception>
    /// <exception cref="ArgumentOutOfRangeException">clientLifetime is not positive, or is over
    /// <see cref="MaxClientLifetime"/></exception>
    public AzureKeyVaultKeyWrapper(Uri wrappingKeyId, Uri signingKeyId, TokenCredential credential,
        string? context = null, KeyFileTrust? keyFileTrust = null, CryptographyClientOptions? options = null,
        TimeSpan? clientLifetime = null)
        : this(wrappingKeyId, signingKeyId, ClientFactory(credential, options), context, keyFileTrust, clientLifetime)
    {
    }

    internal AzureKeyVaultKeyWrapper(Uri wrappingKeyId, Uri signingKeyId, Func<Uri, CryptographyClient> clientFactory,
        string? context, KeyFileTrust? keyFileTrust, TimeSpan? clientLifetime = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(wrappingKeyId);
        ArgumentNullException.ThrowIfNull(signingKeyId);

        var lifetime = clientLifetime ?? DefaultClientLifetime;
        if (lifetime <= TimeSpan.Zero || lifetime > MaxClientLifetime)
            throw new ArgumentOutOfRangeException(nameof(clientLifetime), lifetime,
                $"The client lifetime must be positive and at most {MaxClientLifetime}.");

        _wrappingKey = new KeyVaultKeyIdentifier(wrappingKeyId);
        _signingKey = new KeyVaultKeyIdentifier(signingKeyId);
        if (SameKey(_wrappingKey, _signingKey))
            throw new ArgumentException(
                $"The wrapping and signing keys are both '{_wrappingKey.Name}'; use an RSA key to wrap and a separate EC P-256 key to sign.", nameof(signingKeyId));

        _wrappingKeyId = wrappingKeyId;
        _signingKeyId = signingKeyId;
        _clientFactory = clientFactory;
        _context = WrappedDekEnvelope.EncodeContext(context);
        _keyFileTrust = keyFileTrust ?? KeyFileTrust.AdministratorsOnly;
        ClientLifetime = lifetime;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// How long a Key Vault client is kept for a key version before a fresh one replaces it - and so
    /// how long, at most, a running process goes on verifying under a signing key version that has
    /// been disabled or purged.
    /// </summary>
    public TimeSpan ClientLifetime { get; }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">plaintext is empty or over <see cref="MaxPlaintextLength"/>
    /// bytes, or result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">Key Vault refused a request or could not be reached
    /// (the Azure exception is the inner exception), or the wrapped DEK would be over
    /// <see cref="WrappedKeyLimits.MaxBytes"/> (an RSA key over 3072 bits)</exception>
    public async ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty || plaintext.Length > MaxPlaintextLength)
            throw new ArgumentException($"Azure Key Vault wraps 1-{MaxPlaintextLength} bytes; got {plaintext.Length}.", nameof(plaintext));

        // Pinned, so no copy is left behind by compaction before it is zeroed.
        var buffer = ArrayUtility.AllocatePinned<byte>(plaintext.Length);
        (string Version, byte[] EncryptedKey) wrap;
        try
        {
            plaintext.Span.CopyTo(buffer);
            wrap = await CallAsync(_wrappingKeyId, client => client.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, buffer, cancellationToken),
                    w => (Version: VersionOf(w.KeyId, _wrappingKey, "wrap"), w.EncryptedKey), "wrap", _wrappingKey)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        var unsigned = WrappedDekEnvelope.BuildUnsigned(wrap.Version, wrap.EncryptedKey);
        var length = unsigned.Length + WrappedDekEnvelope.KeyVersionLength + WrappedDekEnvelope.SignatureLength;
        if (length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException(
                $"The wrapped DEK would be {length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MaxBytes}. Use a 2048- or 3072-bit RSA key for '{_wrappingKey.Name}'.");

        var sign = await CallAsync(_signingKeyId, client => client.SignDataAsync(SignatureAlgorithm.ES256, WrappedDekEnvelope.SignedData(unsigned, _context), cancellationToken),
                s => (Version: VersionOf(s.KeyId, _signingKey, "sign"), s.Signature), "sign", _signingKey)
            .ConfigureAwait(false);
        return WrappedDekEnvelope.Write(unsigned, sign.Version, sign.Signature, result.Span);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the revealed key</exception>
    /// <exception cref="CryptographicException">wrapped isn't a wrapped DEK this wrapper wrote, its
    /// signature doesn't verify (forged, tampered with, or under a different context), Key Vault
    /// refused it, or Key Vault could not be reached (the Azure exception is the inner exception)</exception>
    public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        try
        {
            var parts = WrappedDekEnvelope.Parse(wrapped.Span);

            // The signature first: nothing reaches UnwrapKey that a principal allowed to sign didn't make.
            var signed = WrappedDekEnvelope.SignedData(wrapped.Span[..parts.UnsignedLength], _context);
            var signingKeyVersion = parts.SigningKeyVersion;
            await CallAsync(VersionId(_signingKey, signingKeyVersion),
                    client => client.VerifyDataAsync(SignatureAlgorithm.ES256, signed, parts.Signature, cancellationToken),
                    verify => verify.IsValid
                        ? verify
                        : throw new CryptographicException(
                            $"The wrapped DEK's signature doesn't verify under '{_signingKey.Name}' version {signingKeyVersion}: it was tampered with, wrapped under a different context, or not made by a principal allowed to sign."),
                    "verify", _signingKey)
                .ConfigureAwait(false);

            var revealed = await CallAsync(VersionId(_wrappingKey, parts.WrappingKeyVersion),
                    client => client.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, parts.WrappedDek, cancellationToken), unwrap => unwrap.Key, "unwrap", _wrappingKey)
                .ConfigureAwait(false);
            try
            {
                if (revealed.Length > result.Length)
                    throw new ArgumentException($"The revealed key is {revealed.Length} bytes; result holds {result.Length}.", nameof(result));

                revealed.CopyTo(result.Span);
                return revealed.Length;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(revealed);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result.Span);
            throw;
        }
    }

    /// <summary>
    /// Generates a fresh <see cref="GeneratedKeyLength"/>-byte DEK in this process, wraps and signs
    /// it, and zeroes it - it is never returned.
    /// </summary>
    /// <param name="result">The wrapped key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    /// <exception cref="ArgumentException">result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">As <see cref="WrapAsync"/></exception>
    public async ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        var dek = ArrayUtility.AllocatePinned<byte>(GeneratedKeyLength);
        try
        {
            RandomNumberGenerator.Fill(dek);
            return await WrapAsync(dek, result, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>
    /// Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
    /// the operating system's administrators and the <see cref="KeyFileTrust"/> given at
    /// construction could have written or replaced (see <see cref="TrustedKeyFile.ReadAsync"/>).
    /// </summary>
    /// <param name="path">The key file's path</param>
    /// <param name="cancellationToken">Cancels the read</param>
    /// <returns>The file's contents, still wrapped</returns>
    /// <exception cref="FileNotFoundException">The file doesn't exist</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read the file, or it isn't
    /// somewhere only trusted principals can modify</exception>
    /// <exception cref="InvalidDataException">The file is empty, too long, or holds what looks like an unwrapped key</exception>
    /// <exception cref="IOException">The file can't be read, or another process has it open for writing</exception>
    public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => TrustedKeyFile.ReadAsync(path, _keyFileTrust, cancellationToken);

    internal static Func<Uri, CryptographyClient> ClientFactory(TokenCredential credential, CryptographyClientOptions? options)
    {
        ArgumentNullException.ThrowIfNull(credential);
        return keyId => new CryptographyClient(keyId, credential, options ?? new CryptographyClientOptions());
    }

    // The number of clients kept, for tests.
    internal int CachedClientCount => _clients.Count;

    private static Uri VersionId(KeyVaultKeyIdentifier key, string version)
        => new($"{key.VaultUri.AbsoluteUri.TrimEnd('/')}/keys/{key.Name}/{version}");

    private static bool SameKey(KeyVaultKeyIdentifier a, KeyVaultKeyIdentifier b)
        => Uri.Compare(a.VaultUri, b.VaultUri, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0
           && string.Equals(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);

    // The version of the key Key Vault reports having used, refusing an answer from any other key.
    private static string VersionOf(string? keyId, KeyVaultKeyIdentifier expected, string operation)
    {
        KeyVaultKeyIdentifier used;
        try
        {
            used = new KeyVaultKeyIdentifier(new Uri(keyId ?? throw new UriFormatException("no key identifier")));
        }
        catch (Exception e) when (e is UriFormatException or ArgumentException)
        {
            throw new CryptographicException($"Azure Key Vault {operation} for key '{expected.Name}' reported key '{keyId}', which isn't a key identifier.", e);
        }

        if (!SameKey(used, expected) || string.IsNullOrEmpty(used.Version))
            throw new CryptographicException($"Azure Key Vault {operation} for key '{expected.Name}' reported key '{keyId}' instead.");
        return used.Version;
    }

    // Makes one Key Vault call through the client for keyId, and returns what accept makes of its
    // response (accept throws to refuse it). One client per key version is kept: each caches the
    // public key it verifies with, and a ring's refresh unwraps under the same versions every
    // interval. But a client is kept only once a call through it succeeds and its response is
    // accepted: the versions unwrap uses come from the wrapped DEK, so a payload naming a version
    // Key Vault refuses, or whose signature doesn't verify, leaves nothing behind. A kept client is
    // used for ClientLifetime and then dropped, so the next call fetches the key again and a version
    // disabled or purged since is refused (see the class remarks). CryptographyClient holds nothing
    // to dispose, so a client that isn't kept is simply dropped.
    private async Task<TResult> CallAsync<T, TResult>(Uri keyId, Func<CryptographyClient, Task<T>> call, Func<T, TResult> accept,
        string operation, KeyVaultKeyIdentifier key)
    {
        if (_clients.TryGetValue(keyId, out var cached))
        {
            if (_timeProvider.GetElapsedTime(cached.CreatedAt) < ClientLifetime)
                return accept(await CallAsync(() => call(cached.Client), operation, key).ConfigureAwait(false));

            // Expired: never used again, whether or not its replacement succeeds.
            _clients.TryRemove(new KeyValuePair<Uri, (CryptographyClient, long)>(keyId, cached));
        }

        var createdAt = _timeProvider.GetTimestamp();
        var client = _clientFactory(keyId);
        var result = accept(await CallAsync(() => call(client), operation, key).ConfigureAwait(false));
        // Keep the newer of this client and one a concurrent call kept meanwhile.
        _clients.AddOrUpdate(keyId, (client, createdAt),
            (_, existing) => existing.CreatedAt >= createdAt ? existing : (client, createdAt));
        return result;
    }

    // Turns Azure failures - service refusals (RequestFailedException) and client-side ones such as
    // a credential that can't get a token - into the CryptographicException every IKeyWrapper fails
    // with. Cancellation is left as it is.
    private static async Task<T> CallAsync<T>(Func<Task<T>> call, string operation, KeyVaultKeyIdentifier key)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (RequestFailedException e)
        {
            throw new CryptographicException(
                $"Azure Key Vault {operation} failed for key '{key.Name}': {e.ErrorCode ?? "error"} (HTTP {e.Status}).", e);
        }
        catch (Exception e) when (e is not (OperationCanceledException or CryptographicException))
        {
            throw new CryptographicException($"Azure Key Vault {operation} failed for key '{key.Name}': {e.Message}", e);
        }
    }
}
