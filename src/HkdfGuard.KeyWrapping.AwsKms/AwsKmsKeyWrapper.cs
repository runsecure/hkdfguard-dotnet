using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using HkdfGuard.Abstractions;

namespace HkdfGuard.KeyWrapping.AwsKms;

/// <summary>
/// Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric AWS KMS key, and generates
/// fresh DEKs with GenerateDataKeyWithoutPlaintext - so on that path the plaintext DEK never leaves
/// KMS. The KEK never enters this process; every call is a network round trip, authorized by the
/// caller's IAM credentials and recorded in CloudTrail.
/// <para>
/// The key is pinned on every Decrypt. A symmetric ciphertext blob names its own key and KMS would
/// otherwise decrypt it under whichever key it names, so a substituted key file wrapped under any
/// other key this principal may use would be revealed. With the key pinned KMS refuses it
/// (IncorrectKeyException). Prefer a key ARN to an alias: Decrypt resolves an alias when it is
/// called, so re-pointing the alias at a new key makes every DEK wrapped under the old one
/// unreadable. KMS's own automatic key rotation keeps the key ARN and is transparent here.
/// </para>
/// <para>
/// The encryption context, if any, is bound into every wrapped DEK as authenticated data: Decrypt
/// fails unless it is presented again exactly, and key policies can require it
/// (kms:EncryptionContext:*). It is logged in plaintext by CloudTrail, so it must not hold secrets.
/// </para>
/// <para>
/// Plaintext key bytes this class owns - the buffer sent to Encrypt and the stream Decrypt returns
/// - are zeroed once used. The AWS SDK base64-encodes both into JSON strings it does not expose,
/// which can't be zeroed and live until collected.
/// </para>
/// </summary>
public sealed class AwsKmsKeyWrapper : IKeyWrapper
{
    /// <summary>The length of the DEK <see cref="GenerateAndWrapAsync"/> generates: 32 bytes (AES-256).</summary>
    public const int GeneratedKeyLength = 32;

    /// <summary>The largest plaintext KMS's Encrypt accepts, in bytes.</summary>
    public const int MaxPlaintextLength = 4096;

    private readonly IAmazonKeyManagementService _client;
    private readonly string _keyId;
    private readonly Dictionary<string, string>? _encryptionContext;

    /// <param name="client">The KMS client every call is made through. Not disposed by this wrapper;
    /// its owner (typically the DI container) disposes it.</param>
    /// <param name="keyId">The symmetric KMS key that wraps every DEK: a key ARN (preferred), key ID,
    /// alias name ("alias/...") or alias ARN.</param>
    /// <param name="encryptionContext">Bound into every wrapped DEK and required again to reveal
    /// it. Copied at construction; null or empty binds none.</param>
    /// <exception cref="ArgumentNullException">client or keyId is null, or the context holds a null value</exception>
    /// <exception cref="ArgumentException">keyId is empty or whitespace, or the context holds an empty key</exception>
    public AwsKmsKeyWrapper(IAmazonKeyManagementService client, string keyId,
        IReadOnlyDictionary<string, string>? encryptionContext = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        _client = client;
        _keyId = keyId;

        if (encryptionContext is { Count: > 0 })
        {
            _encryptionContext = new Dictionary<string, string>(encryptionContext.Count, StringComparer.Ordinal);
            foreach (var (key, value) in encryptionContext)
            {
                if (string.IsNullOrEmpty(key))
                    throw new ArgumentException("Encryption context keys must not be empty.", nameof(encryptionContext));
                ArgumentNullException.ThrowIfNull(value, $"{nameof(encryptionContext)}[\"{key}\"]");
                _encryptionContext.Add(key, value);
            }
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">plaintext is empty or over <see cref="MaxPlaintextLength"/>
    /// bytes, or result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">KMS refused the request, or could not be reached
    /// (the AWS exception is the inner exception), or returned a wrapped DEK over
    /// <see cref="WrappedKeyLimits.MaxBytes"/></exception>
    public async ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty || plaintext.Length > MaxPlaintextLength)
            throw new ArgumentException($"KMS wraps 1-{MaxPlaintextLength} bytes; got {plaintext.Length}.", nameof(plaintext));

        // Pinned, so no copy is left behind by compaction before it is zeroed.
        var buffer = ArrayUtility.AllocatePinned<byte>(plaintext.Length);
        try
        {
            plaintext.Span.CopyTo(buffer);
            var request = new EncryptRequest
            {
                KeyId = _keyId,
                Plaintext = new MemoryStream(buffer, writable: false),
                EncryptionContext = CopyEncryptionContext(),
                EncryptionAlgorithm = EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT,
            };

            var response = await CallAsync(() => _client.EncryptAsync(request, cancellationToken), "wrap").ConfigureAwait(false);
            return CopyWrapped(response.CiphertextBlob, result, "wrap");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">result is too small for the revealed key</exception>
    /// <exception cref="CryptographicException">wrapped is empty or over
    /// <see cref="WrappedKeyLimits.MaxBytes"/>, or KMS refused it - tampered with, wrapped under
    /// another key, or under a different encryption context - or could not be reached (the AWS
    /// exception is the inner exception)</exception>
    public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        // Refused locally: no ciphertext this wrapper produced is outside these bounds.
        if (wrapped.IsEmpty || wrapped.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException($"A wrapped DEK is 1-{WrappedKeyLimits.MaxBytes} bytes; got {wrapped.Length}.");

        try
        {
            var request = new DecryptRequest
            {
                KeyId = _keyId,
                CiphertextBlob = new MemoryStream(wrapped.ToArray(), writable: false),
                EncryptionContext = CopyEncryptionContext(),
                EncryptionAlgorithm = EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT,
            };

            var response = await CallAsync(() => _client.DecryptAsync(request, cancellationToken), "unwrap").ConfigureAwait(false);
            using var revealed = response.Plaintext
                ?? throw new CryptographicException($"AWS KMS unwrap for key '{_keyId}' returned no plaintext.");
            try
            {
                if (revealed.Length > result.Length)
                    throw new ArgumentException($"The revealed key is {revealed.Length} bytes; result holds {result.Length}.", nameof(result));

                var length = (int)revealed.Length;
                revealed.Position = 0;
                revealed.ReadExactly(result.Span[..length]);
                return length;
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
    /// Has KMS generate a fresh <see cref="GeneratedKeyLength"/>-byte DEK and return it wrapped
    /// only (GenerateDataKeyWithoutPlaintext) - the plaintext DEK never leaves KMS on this call.
    /// </summary>
    /// <param name="result">The wrapped key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    /// <exception cref="ArgumentException">result is too small for the wrapped DEK</exception>
    /// <exception cref="CryptographicException">KMS refused the request, or could not be reached
    /// (the AWS exception is the inner exception), or returned a wrapped DEK over
    /// <see cref="WrappedKeyLimits.MaxBytes"/></exception>
    public async ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        var request = new GenerateDataKeyWithoutPlaintextRequest
        {
            KeyId = _keyId,
            KeySpec = DataKeySpec.AES_256,
            EncryptionContext = CopyEncryptionContext(),
        };

        var response = await CallAsync(() => _client.GenerateDataKeyWithoutPlaintextAsync(request, cancellationToken), "generate-and-wrap")
            .ConfigureAwait(false);
        return CopyWrapped(response.CiphertextBlob, result, "generate-and-wrap");
    }

    // A fresh dictionary per request, so nothing the SDK (or a handler in its pipeline) does to a
    // request can change what later requests bind.
    private Dictionary<string, string>? CopyEncryptionContext()
        => _encryptionContext is null ? null : new Dictionary<string, string>(_encryptionContext, StringComparer.Ordinal);

    // Turns AWS failures - service refusals (AmazonServiceException) and client-side ones such as
    // unresolvable credentials (AmazonClientException) - into the CryptographicException every
    // IKeyWrapper fails with, naming KMS's error code. Cancellation is left as it is.
    private async Task<T> CallAsync<T>(Func<Task<T>> call, string operation)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (AmazonServiceException e)
        {
            throw new CryptographicException(
                $"AWS KMS {operation} failed for key '{_keyId}': {e.ErrorCode ?? e.GetType().Name} (HTTP {(int)e.StatusCode}).", e);
        }
        catch (AmazonClientException e)
        {
            throw new CryptographicException($"AWS KMS {operation} failed for key '{_keyId}': {e.Message}", e);
        }
    }

    private int CopyWrapped(MemoryStream? ciphertext, Memory<byte> result, string operation)
    {
        if (ciphertext is null || ciphertext.Length == 0)
            throw new CryptographicException($"AWS KMS {operation} for key '{_keyId}' returned no ciphertext.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (ciphertext.Length > WrappedKeyLimits.MaxBytes)
            throw new CryptographicException(
                $"AWS KMS {operation} for key '{_keyId}' returned {ciphertext.Length} bytes; a wrapped DEK is at most {WrappedKeyLimits.MaxBytes}.");

        if (ciphertext.Length > result.Length)
            throw new ArgumentException($"The wrapped DEK is {ciphertext.Length} bytes; result holds {result.Length}.", nameof(result));

        var length = (int)ciphertext.Length;
        ciphertext.Position = 0;
        ciphertext.ReadExactly(result.Span[..length]);
        return length;
    }

    // Zeroes a stream's backing array in place. The SDK builds its streams over arrays it does not
    // expose (so TryGetBuffer fails), but they are writable: overwriting from the start reaches the
    // same array.
    internal static void Scrub(MemoryStream stream)
    {
        if (stream.TryGetBuffer(out var buffer))
        {
            CryptographicOperations.ZeroMemory(buffer);
            return;
        }

        if (!stream.CanWrite)
            return;

        Span<byte> zeros = stackalloc byte[64];
        zeros.Clear();
        stream.Position = 0;
        for (var remaining = stream.Length; remaining > 0; remaining -= zeros.Length)
            stream.Write(zeros[..(int)Math.Min(remaining, zeros.Length)]);
    }
}
