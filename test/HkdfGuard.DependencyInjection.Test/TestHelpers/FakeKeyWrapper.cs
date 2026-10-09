using HkdfGuard.Abstractions;

namespace HkdfGuard.DependencyInjection.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key - isolates AddKeyRing tests
/// from any real native KMS machinery.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }

    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }
}
