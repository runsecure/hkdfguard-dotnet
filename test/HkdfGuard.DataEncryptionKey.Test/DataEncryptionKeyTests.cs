using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class DataEncryptionKeyTests
{
    private static async Task<(DataEncryptionKey Key, FakeKeyWrapper Wrapper)> CreateKeyAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        return (new DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60)), wrapper);
    }

    [Fact]
    public async Task EncryptDecrypt_RoundTrips()
    {
        var dataProtectionKey = (await CreateKeyAsync()).Key;
        var plaintext = "top secret"u8.ToArray();
        // AesGcmCryptoSession.Encrypt zeroes the plaintext span it's given as a side effect.
        var expected = (byte[])plaintext.Clone();

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        Assert.Equal(expected.Length + 12 + 16, encrypted.Length);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, decryptedLength);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_WithAad_RoundTrips()
    {
        var dataProtectionKey = (await CreateKeyAsync()).Key;
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var aad = "context"u8.ToArray();

        var encrypted = dataProtectionKey.Encrypt(plaintext, aad);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public async Task Decrypt_WithMismatchedAad_Throws()
    {
        var dataProtectionKey = (await CreateKeyAsync()).Key;
        var plaintext = "top secret"u8.ToArray();
        var encrypted = dataProtectionKey.Encrypt(plaintext, "context-a"u8.ToArray());

        var result = new byte[plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            dataProtectionKey.Decrypt(encrypted, "context-b"u8.ToArray(), result));
    }

    [Fact]
    public async Task EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var loggingScope = new SensitiveLoggingScope(true);

        var dataProtectionKey = (await CreateKeyAsync()).Key;
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public async Task Encrypt_ReturnsExactlySizedArray()
    {
        var dataProtectionKey = (await CreateKeyAsync()).Key;
        var plaintext = "a longer plaintext value to encrypt"u8.ToArray();
        var expectedLength = plaintext.Length + 12 + 16; // AES-GCM nonce + tag overhead

        var encrypted = dataProtectionKey.Encrypt(plaintext);

        Assert.Equal(expectedLength, encrypted.Length);
    }

    [Fact]
    public async Task EncryptAndDecrypt_ReuseTheCachedSessionAcrossCalls()
    {
        // AesGcmCryptoSessionProvider only calls back into the key wrapper when it has no cached
        // session yet or the cached one has expired - not on every operation - so a wrapper's
        // key is revealed once here, then reused for every subsequent Encrypt/Decrypt.
        var (dataProtectionKey, wrapper) = await CreateKeyAsync();
        var encrypted1 = dataProtectionKey.Encrypt("one"u8.ToArray());
        var encrypted2 = dataProtectionKey.Encrypt("two"u8.ToArray());

        dataProtectionKey.Decrypt(encrypted1, new byte[3]);
        dataProtectionKey.Decrypt(encrypted2, new byte[3]);

        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public async Task Dispose_DisposesTheProvider()
    {
        var key = (await CreateKeyAsync()).Key;

        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.Encrypt("top secret"u8.ToArray()));
    }

    [Fact]
    public void Dispose_CalledTwice_DisposesTheProviderOnce()
    {
        var provider = new CountingDisposeProvider();
        var key = new DataEncryptionKey(provider);

        key.Dispose();
        key.Dispose();

        Assert.Equal(1, provider.DisposeCount);
    }

    [Fact]
    public async Task DisposeAsync_DisposesTheProviderAsynchronously()
    {
        var (key, _) = await CreateKeyAsync();

        await key.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => key.Encrypt("top secret"u8.ToArray()));
    }

    [Fact]
    public async Task DisposeAsync_CalledTwiceOrAfterDispose_DisposesTheProviderOnce()
    {
        var provider = new CountingDisposeProvider();
        var key = new DataEncryptionKey(provider);

        await key.DisposeAsync();
        await key.DisposeAsync();
        key.Dispose();

        Assert.Equal(1, provider.DisposeAsyncCount);
        Assert.Equal(0, provider.DisposeCount);
    }

    private sealed class CountingDisposeProvider : ICryptoProvider
    {
        public int DisposeCount { get; private set; }
        public int Encrypt(Span<byte> plaintext, Span<byte> result) => throw new NotSupportedException();
        public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result) => throw new NotSupportedException();
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => throw new NotSupportedException();
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => throw new NotSupportedException();
        public int GetEncryptedAllocationLength(int length) => length;
        public int GetDecryptedAllocationLength(int length) => length;
        public int DisposeAsyncCount { get; private set; }
        public void Dispose() => DisposeCount++;
        public ValueTask DisposeAsync()
        {
            DisposeAsyncCount++;
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public void Encrypt_WhenTheProviderOverAllocates_TrimsToWhatWasWritten()
    {
        using var key = new DataEncryptionKey(new OverAllocatingProvider());

        var encrypted = key.Encrypt("abc"u8.ToArray());

        Assert.Equal("abc"u8.ToArray(), encrypted);
    }

    [Fact]
    public async Task Encrypt_WhenTheProviderSizesExactly_ReturnsTheWholeBuffer()
    {
        using var key = (await CreateKeyAsync()).Key;

        var encrypted = key.Encrypt("abc"u8.ToArray());

        Assert.Equal(3 + 12 + 16, encrypted.Length);
    }

    // Asks for 10 spare bytes and "encrypts" by copying - stands in for a provider whose exact
    // ciphertext size isn't known up front.
    private sealed class OverAllocatingProvider : ICryptoProvider
    {
        public int Encrypt(Span<byte> plaintext, Span<byte> result) => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);
        public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
        {
            plaintext.CopyTo(result);
            return plaintext.Length;
        }
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => throw new NotSupportedException();
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => throw new NotSupportedException();
        public int GetEncryptedAllocationLength(int length) => length + 10;
        public int GetDecryptedAllocationLength(int length) => length;
        public void Dispose() { }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
