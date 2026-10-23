using HkdfGuard.Abstractions;

namespace HkdfGuard.EncryptedConfiguration.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals the same fixed key - isolates ProtectedConfigurationRoot
/// tests from the real blob/file/OS-storage machinery (already covered elsewhere) while still
/// exercising real AES-GCM via a real ICryptoSession.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    // Test-only: a plain read. Real key wrappers must refuse a key file another account could have replaced.
    public async ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);

    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }

    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");
}
