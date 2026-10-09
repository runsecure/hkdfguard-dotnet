using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.EncryptedConfiguration.Test.TestHelpers;

/// <summary>
/// Stands in for the native platform's key wrapper in end-to-end tests: a KEK held only in this
/// instance's memory, with real AES-256-GCM wrapping (nonce | ciphertext | tag) - so a key file
/// produced by WrapAsync is genuinely wrapped, and unwrapping a tampered payload, or one wrapped
/// under a different TestKekWrapper, fails exactly as the native library would.
/// </summary>
internal sealed class TestKekWrapper : IKeyWrapper
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _kek = RandomNumberGenerator.GetBytes(32);

    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        var output = result.Span;
        var length = NonceSize + plaintext.Length + TagSize;
        RandomNumberGenerator.Fill(output[..NonceSize]);
        using var aes = new AesGcm(_kek, TagSize);
        aes.Encrypt(output[..NonceSize], plaintext.Span, output.Slice(NonceSize, plaintext.Length), output.Slice(NonceSize + plaintext.Length, TagSize));
        return ValueTask.FromResult(length);
    }

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        var input = wrapped.Span;
        var dekLength = input.Length - NonceSize - TagSize;
        try
        {
            using var aes = new AesGcm(_kek, TagSize);
            aes.Decrypt(input[..NonceSize], input.Slice(NonceSize, dekLength), input[^TagSize..], result.Span[..dekLength]);
            return ValueTask.FromResult(dekLength);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(result.Span);
            return ValueTask.FromException<int>(ex);
        }
    }

    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        try
        {
            return WrapAsync(dek, result, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }
}
