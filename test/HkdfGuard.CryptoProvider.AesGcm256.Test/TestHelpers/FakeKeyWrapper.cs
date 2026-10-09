using HkdfGuard.Abstractions;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals a fresh random key, tracking how many times Decrypt was
/// called - isolates AesGcmCryptoSessionProvider tests from any real native KMS machinery.
/// </summary>
internal sealed class FakeKeyWrapper : IKeyWrapper
{
    public int DecryptCallCount { get; private set; }
    public int GenerateAndWrapCallCount { get; private set; }

    /// <summary>
    /// When set, Decrypt throws this instead of revealing a key.
    /// </summary>
    public Exception? ThrowOnDecrypt { get; set; }

    /// <summary>
    /// When set, UnwrapAsync fills only this many bytes and reports that count - models a wrapper
    /// backed by a key of the wrong size (e.g. a KMS data key generated as AES-128).
    /// </summary>
    public int? UnwrapBytesWrittenOverride { get; set; }

    /// <summary>
    /// When set, UnwrapAsync reveals this same key every time (as a real wrapper does for one
    /// wrapped payload) instead of a fresh random one - needed by any test that decrypts across
    /// a background refresh.
    /// </summary>
    public byte[]? FixedKey { get; init; }

    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        DecryptCallCount++;
        if (ThrowOnDecrypt is not null)
            throw ThrowOnDecrypt;

        var written = UnwrapBytesWrittenOverride ?? result.Length;
        var target = result.Span[..Math.Min(written, result.Length)];
        if (FixedKey is null)
            System.Security.Cryptography.RandomNumberGenerator.Fill(target);
        else
            FixedKey.AsSpan(0, target.Length).CopyTo(target);
        return ValueTask.FromResult(written);
    }

    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        GenerateAndWrapCallCount++;
        System.Security.Cryptography.RandomNumberGenerator.Fill(result.Span[..32]);
        return ValueTask.FromResult(32);
    }
}
