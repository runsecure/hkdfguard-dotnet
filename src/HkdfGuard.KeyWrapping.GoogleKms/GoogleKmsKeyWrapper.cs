using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Google.Api.Gax.Grpc;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Grpc.Core;
using HkdfGuard.Abstractions;
using HkdfGuard.SecureFile;

namespace HkdfGuard.KeyWrapping.GoogleKms;

/// <summary>
/// Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric Google Cloud KMS key
/// (purpose ENCRYPT_DECRYPT). The KEK never enters this process; every call is a network round
/// trip, authorized by the caller's Google credential through IAM and recorded in Cloud Audit Logs.
/// <para>
/// The key is pinned: Decrypt is always called against the key given at construction, and Cloud
/// KMS refuses a ciphertext made under any other key, so a substituted key file wrapped under
/// another key this principal may use is never revealed. A ciphertext names the key version that
/// made it, so Cloud KMS's own key rotation is transparent here - each key file keeps decrypting
/// under its version, which must stay enabled while the file is in use.
/// </para>
/// <para>
/// Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard label and the
/// optional context: Decrypt fails unless both are presented again exactly. The label stops a
/// ciphertext the same key made for some other purpose being accepted as a DEK; the context stops a
/// key file made for one application being used by another that shares the key. Neither is secret.
/// </para>
/// <para>
/// Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
/// <c>cloudkms.cryptoKeyVersions.useToEncrypt</c> can make a key file this wrapper accepts. Give
/// the application decrypt only (roles/cloudkms.cryptoKeyDecrypter) and the pipeline that creates
/// key files encrypt only; and key files are read only from where an untrusted account can't have
/// written or replaced them (see <see cref="ReadKeyFileAsync"/> and <see cref="KeyFileTrust"/>).
/// </para>
/// <para>
/// Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
/// transit is refused rather than stored or used. Cloud KMS has no "generate data key", so
/// <see cref="GenerateAndWrapAsync"/> generates the DEK in this process, wraps it, and zeroes it.
/// Plaintext key bytes this class owns - the buffer sent to Encrypt and the bytes Decrypt returns
/// - are zeroed once used; the gRPC stack's own copies can't be, and live until collected.
/// </para>
/// </summary>
public sealed class GoogleKmsKeyWrapper : IKeyWrapper
{
    /// <summary>The length of the DEK <see cref="GenerateAndWrapAsync"/> generates: 32 bytes (AES-256).</summary>
    public const int GeneratedKeyLength = 32;

    /// <summary>The largest plaintext Cloud KMS's Encrypt accepts, in bytes.</summary>
    public const int MaxPlaintextLength = 64 * 1024;

    /// <summary>The longest context, in UTF-8 bytes: what Cloud KMS's additional authenticated data
    /// allows, less the HkdfGuard label.</summary>
    public const int MaxContextLength = 64 * 1024 - 32;

    // Prefixed to every wrapped DEK's additional authenticated data. Changing it makes every
    // existing key file unreadable.
    private static ReadOnlySpan<byte> AadLabel => "HkdfGuard-GoogleKms-wrap-v1\0"u8;

    private readonly KeyManagementServiceClient _client;
    private readonly string _keyName;
    private readonly byte[] _aad;
    private readonly long _aadCrc32C;
    private readonly KeyFileTrust _keyFileTrust;

    /// <param name="client">The Cloud KMS client every call is made through, e.g. from
    /// <see cref="KeyManagementServiceClient.Create()"/>. Not owned by this wrapper.</param>
    /// <param name="keyName">The symmetric key that wraps every DEK, as its resource name:
    /// projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}. Not a key
    /// version: Decrypt takes the key, and Encrypt uses its primary version.</param>
    /// <param name="context">Bound into every wrapped DEK and required again to reveal it; null or
    /// empty binds none. Not secret.</param>
    /// <param name="keyFileTrust">Who besides the operating system's administrators may have
    /// written a key file <see cref="ReadKeyFileAsync"/> reads; null trusts administrators only
    /// (<see cref="KeyFileTrust.AdministratorsOnly"/>).</param>
    /// <exception cref="ArgumentNullException">client or keyName is null</exception>
    /// <exception cref="ArgumentException">keyName isn't a Cloud KMS key's resource name, or the
    /// context is over <see cref="MaxContextLength"/> bytes</exception>
    public GoogleKmsKeyWrapper(KeyManagementServiceClient client, string keyName,
        string? context = null, KeyFileTrust? keyFileTrust = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(keyName);
        if (!CryptoKeyName.TryParse(keyName, out var parsed))
            throw new ArgumentException(
                $"'{keyName}' isn't a Cloud KMS key's resource name: projects/{{project}}/locations/{{location}}/keyRings/{{keyRing}}/cryptoKeys/{{key}}, without a key version.",
                nameof(keyName));

        var contextBytes = Encoding.UTF8.GetBytes(context ?? "");
        if (contextBytes.Length > MaxContextLength)
            throw new ArgumentException($"The context is {contextBytes.Length} bytes in UTF-8; at most {MaxContextLength} are allowed.", nameof(context));

        _client = client;
        _keyName = parsed.ToString();
        _aad = [.. AadLabel, .. contextBytes];
        _aadCrc32C = Crc32C(_aad);
        _keyFileTrust = keyFileTrust ?? KeyFileTrust.AdministratorsOnly;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">plaintext is empty or over <see cref="MaxPlaintextLength"/>
    /// bytes, or result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">Cloud KMS refused the request or could not be reached
    /// (the gRPC exception is the inner exception), the request or response was corrupted in
    /// transit, or the wrapped DEK is over <see cref="WrappedKeyLimits.MaxBytes"/></exception>
    public async ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty || plaintext.Length > MaxPlaintextLength)
            throw new ArgumentException($"Cloud KMS wraps 1-{MaxPlaintextLength} bytes; got {plaintext.Length}.", nameof(plaintext));

        // Pinned, so no copy is left behind by compaction before it is zeroed; wrapped rather than
        // copied into the request, so zeroing it reaches the bytes the request holds.
        var buffer = ArrayUtility.AllocatePinned<byte>(plaintext.Length);
        EncryptResponse response;
        try
        {
            plaintext.Span.CopyTo(buffer);
            var request = new EncryptRequest
            {
                Name = _keyName,
                Plaintext = UnsafeByteOperations.UnsafeWrap(buffer),
                PlaintextCrc32C = Crc32C(buffer),
                AdditionalAuthenticatedData = ByteString.CopyFrom(_aad),
                AdditionalAuthenticatedDataCrc32C = _aadCrc32C,
            };
            response = await CallAsync(() => _client.EncryptAsync(request, CallSettings.FromCancellationToken(cancellationToken)), "wrap", cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        // The version that made it must be one of this key's: a response for any other key would
        // produce a key file this wrapper can't read back.
        if (!response.Name.StartsWith($"{_keyName}/cryptoKeyVersions/", StringComparison.Ordinal)
            || !CryptoKeyVersionName.TryParse(response.Name, out _))
            throw new CryptographicException($"Cloud KMS wrap for key '{_keyName}' reported key version '{response.Name}' instead.");

        if (!response.VerifiedPlaintextCrc32C || !response.VerifiedAdditionalAuthenticatedDataCrc32C)
            throw new CryptographicException($"Cloud KMS wrap for key '{_keyName}' didn't verify the request's checksums: it was corrupted in transit.");

        var ciphertext = response.Ciphertext.Span;
        if (ciphertext.IsEmpty)
            throw new CryptographicException($"Cloud KMS wrap for key '{_keyName}' returned no ciphertext.");
        if (response.CiphertextCrc32C != Crc32C(ciphertext))
            throw new CryptographicException($"Cloud KMS wrap for key '{_keyName}' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (ciphertext.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException(
                $"Cloud KMS wrap for key '{_keyName}' returned {ciphertext.Length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MaxBytes}.");
        if (ciphertext.Length > result.Length)
            throw new ArgumentException($"The wrapped DEK is {ciphertext.Length} bytes; result holds {result.Length}.", nameof(result));

        ciphertext.CopyTo(result.Span);
        return ciphertext.Length;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the revealed key</exception>
    /// <exception cref="CryptographicException">wrapped is empty or over
    /// <see cref="WrappedKeyLimits.MaxBytes"/>, or Cloud KMS refused it - tampered with, wrapped
    /// under another key, or under a different context - or could not be reached (the gRPC
    /// exception is the inner exception), or the response was corrupted in transit</exception>
    public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        // Refused locally: no ciphertext this wrapper produced is outside these bounds.
        if (wrapped.IsEmpty || wrapped.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException($"A wrapped DEK is 1-{WrappedKeyLimits.MaxBytes} bytes; got {wrapped.Length}.");

        try
        {
            var request = new DecryptRequest
            {
                Name = _keyName,
                Ciphertext = ByteString.CopyFrom(wrapped.Span),
                CiphertextCrc32C = Crc32C(wrapped.Span),
                AdditionalAuthenticatedData = ByteString.CopyFrom(_aad),
                AdditionalAuthenticatedDataCrc32C = _aadCrc32C,
            };
            var response = await CallAsync(() => _client.DecryptAsync(request, CallSettings.FromCancellationToken(cancellationToken)), "unwrap", cancellationToken)
                .ConfigureAwait(false);

            var revealed = response.Plaintext;
            try
            {
                if (revealed.IsEmpty)
                    throw new CryptographicException($"Cloud KMS unwrap for key '{_keyName}' returned no plaintext.");
                if (response.PlaintextCrc32C != Crc32C(revealed.Span))
                    throw new CryptographicException($"Cloud KMS unwrap for key '{_keyName}' returned a plaintext that doesn't match its checksum: it was corrupted in transit.");
                if (revealed.Length > result.Length)
                    throw new ArgumentException($"The revealed key is {revealed.Length} bytes; result holds {result.Length}.", nameof(result));

                revealed.Span.CopyTo(result.Span);
                return revealed.Length;
            }
            finally
            {
                Scrub(revealed);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result.Span);
            throw;
        }
    }

    /// <summary>
    /// Generates a fresh <see cref="GeneratedKeyLength"/>-byte DEK in this process, wraps it, and
    /// zeroes it - it is never returned.
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
    /// <exception cref="ArgumentException">The <see cref="KeyFileTrust"/> names a principal that can't be trusted</exception>
    public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => TrustedKeyFile.ReadAsync(path, _keyFileTrust, cancellationToken);

    /// <summary>CRC32C (Castagnoli), as Cloud KMS checksums requests and responses.</summary>
    internal static long Crc32C(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var b in data)
            crc = BitOperations.Crc32C(crc, b);
        return ~crc;
    }

    // Zeroes the bytes a ByteString holds. ByteString is immutable to callers, but its memory is
    // an ordinary array the gRPC stack deserialized into, and nothing else holds this one.
    internal static void Scrub(ByteString bytes)
        => CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(bytes.Memory).Span);

    // Turns Cloud KMS failures - service refusals and transport failures (RpcException), and
    // client-side ones such as a credential that can't get a token - into the CryptographicException
    // every IKeyWrapper fails with, naming the gRPC status. Cancellation is left as cancellation:
    // gRPC reports it as an RpcException, so that one is turned back.
    private async Task<T> CallAsync<T>(Func<Task<T>> call, string operation, CancellationToken cancellationToken)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.Cancelled && cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException($"Cloud KMS {operation} for key '{_keyName}' was canceled.", e, cancellationToken);
        }
        catch (RpcException e)
        {
            throw new CryptographicException($"Cloud KMS {operation} failed for key '{_keyName}': {e.StatusCode}: {e.Status.Detail}", e);
        }
        catch (Exception e) when (e is not (OperationCanceledException or CryptographicException))
        {
            throw new CryptographicException($"Cloud KMS {operation} failed for key '{_keyName}': {e.Message}", e);
        }
    }
}
