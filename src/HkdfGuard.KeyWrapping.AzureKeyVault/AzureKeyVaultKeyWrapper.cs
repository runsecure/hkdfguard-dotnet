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
/// version that made them, which must stay enabled while they're in use.
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

    private readonly KeyVaultKeyIdentifier _wrappingKey;
    private readonly KeyVaultKeyIdentifier _signingKey;
    private readonly Uri _wrappingKeyId;
    private readonly Uri _signingKeyId;
    private readonly Func<Uri, CryptographyClient> _clientFactory;
    private readonly ConcurrentDictionary<Uri, CryptographyClient> _clients = new();
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
    /// <exception cref="ArgumentNullException">A key identifier or the credential is null</exception>
    /// <exception cref="ArgumentException">A key identifier isn't a Key Vault key's, both name the
    /// same key, or the context is too long</exception>
    public AzureKeyVaultKeyWrapper(Uri wrappingKeyId, Uri signingKeyId, TokenCredential credential,
        string? context = null, KeyFileTrust? keyFileTrust = null, CryptographyClientOptions? options = null)
        : this(wrappingKeyId, signingKeyId, ClientFactory(credential, options), context, keyFileTrust)
    {
    }

    internal AzureKeyVaultKeyWrapper(Uri wrappingKeyId, Uri signingKeyId, Func<Uri, CryptographyClient> clientFactory,
        string? context, KeyFileTrust? keyFileTrust)
    {
        ArgumentNullException.ThrowIfNull(wrappingKeyId);
        ArgumentNullException.ThrowIfNull(signingKeyId);

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
    }

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
        WrapResult wrap;
        try
        {
            plaintext.Span.CopyTo(buffer);
            wrap = await CallAsync(() => Client(_wrappingKeyId).WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, buffer, cancellationToken), "wrap", _wrappingKey)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        var unsigned = WrappedDekEnvelope.BuildUnsigned(VersionOf(wrap.KeyId, _wrappingKey, "wrap"), wrap.EncryptedKey);
        var length = unsigned.Length + WrappedDekEnvelope.KeyVersionLength + WrappedDekEnvelope.SignatureLength;
        if (length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException(
                $"The wrapped DEK would be {length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MaxBytes}. Use a 2048- or 3072-bit RSA key for '{_wrappingKey.Name}'.");

        var sign = await CallAsync(() => Client(_signingKeyId).SignDataAsync(SignatureAlgorithm.ES256, WrappedDekEnvelope.SignedData(unsigned, _context), cancellationToken), "sign", _signingKey)
            .ConfigureAwait(false);
        return WrappedDekEnvelope.Write(unsigned, VersionOf(sign.KeyId, _signingKey, "sign"), sign.Signature, result.Span);
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
            var verify = await CallAsync(() => Client(VersionId(_signingKey, parts.SigningKeyVersion))
                    .VerifyDataAsync(SignatureAlgorithm.ES256, signed, parts.Signature, cancellationToken), "verify", _signingKey)
                .ConfigureAwait(false);
            if (!verify.IsValid)
                throw new CryptographicException(
                    $"The wrapped DEK's signature doesn't verify under '{_signingKey.Name}' version {parts.SigningKeyVersion}: it was tampered with, wrapped under a different context, or not made by a principal allowed to sign.");

            var unwrap = await CallAsync(() => Client(VersionId(_wrappingKey, parts.WrappingKeyVersion))
                    .UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, parts.WrappedDek, cancellationToken), "unwrap", _wrappingKey)
                .ConfigureAwait(false);

            var revealed = unwrap.Key;
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

    // One client per key version, kept: each caches the public key it verifies with, and a ring's
    // refresh unwraps under the same versions every interval.
    private CryptographyClient Client(Uri keyId) => _clients.GetOrAdd(keyId, _clientFactory);

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
