using HkdfGuard.Abstractions;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key, tracking how many times
/// Decrypt/GenerateAndWrap were called - isolates
/// DataEncryptionKey/EphemeralDataEncryptionKey/KeyRing tests from the real native KMS
/// machinery while still exercising real AES-GCM via a real ICryptoSession.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int DecryptCallCount { get; private set; }
    public int GenerateAndWrapCallCount { get; private set; }

    /// <summary>
    /// When set, Decrypt throws this instead of revealing the key - lets tests exercise a
    /// DataEncryptionKey Encrypt/Decrypt catch block without depending on the real
    /// cipher failing.
    /// </summary>
    public Exception? ThrowOnDecrypt { get; set; }

    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        DecryptCallCount++;
        if (ThrowOnDecrypt is not null)
            throw ThrowOnDecrypt;

        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }

    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        GenerateAndWrapCallCount++;
        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }
}
