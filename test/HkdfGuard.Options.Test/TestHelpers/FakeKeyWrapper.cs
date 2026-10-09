using HkdfGuard.Abstractions;

namespace HkdfGuard.Options.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key - isolates ApplyTo/Build
/// integration tests from the real native KMS machinery while still exercising a real
/// KeyRingBuilder.Build.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

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
