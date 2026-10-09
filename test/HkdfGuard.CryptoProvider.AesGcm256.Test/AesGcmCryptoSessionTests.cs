using System.Collections.Concurrent;
using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

public class AesGcmCryptoSessionTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 28];

        var written = cipher.Encrypt(plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[expectedPlaintext.Length];
        var decryptedLength = cipher.Decrypt(encrypted, decrypted);

        Assert.Equal(expectedPlaintext.Length, decryptedLength);
        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var aad = "context"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        cipher.Encrypt(plaintext, aad, encrypted);

        var decrypted = new byte[expectedPlaintext.Length];
        cipher.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, "correct-aad"u8.ToArray(), encrypted);

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            cipher.Decrypt(encrypted, "wrong-aad"u8.ToArray(), decrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, encrypted);
        encrypted[15] ^= 0xFF;

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted, decrypted));
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var tooSmall = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(plaintext, tooSmall));
    }

    [Fact]
    public void Decrypt_WithTooShortCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var tooShort = new byte[10];
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(tooShort, result));
    }

    [Fact]
    public void Constructor_WithInvalidKeySize_Throws()
    {
        var invalidKey = RandomNumberGenerator.GetBytes(10);

        Assert.Throws<ArgumentException>(() => new AesGcmCryptoSession(invalidKey));
    }

    [Fact]
    public void Constructor_WithAllZeroKey_Throws()
    {
        var zeroKey = new byte[32];

        Assert.Throws<ArgumentException>(() => new AesGcmCryptoSession(zeroKey));
    }

    [Fact]
    public void Encrypt_WithAllZeroPlaintext_RoundTrips()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var encrypted = new byte[11 + 28];

        var written = cipher.Encrypt(new byte[11], encrypted);
        var decrypted = new byte[11];
        var decryptedLength = cipher.Decrypt(encrypted.AsSpan(0, written), decrypted);

        Assert.Equal(11, decryptedLength);
        Assert.All(decrypted, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Encrypt_WithEmptyPlaintext_RoundTripsToAnAuthenticatedEmptyMessage()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var encrypted = new byte[28];

        var written = cipher.Encrypt(Span<byte>.Empty, "aad"u8, encrypted);

        Assert.Equal(28, written);
        Assert.Equal(0, cipher.Decrypt(encrypted, "aad"u8, Span<byte>.Empty));
        Assert.Throws<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted, "other"u8, Span<byte>.Empty));
    }

    [Fact]
    public void Decrypt_WithEmptyCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(ReadOnlySpan<byte>.Empty, new byte[4]));
    }

    [Fact]
    public void Decrypt_WithNonZeroButTooShortCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var tooShort = RandomNumberGenerator.GetBytes(10); // non-zero, but shorter than nonce + tag
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(tooShort, result));
    }

    [Fact]
    public void Decrypt_WithTooSmallResultBuffer_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, encrypted);

        var tooSmall = new byte[plaintext.Length - 1];
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(encrypted, tooSmall));
    }

    [Fact]
    public void Dispose_ZeroesTheKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var keyClone = (byte[])key.Clone();
        var cipher = new AesGcmCryptoSession(key);

        cipher.Dispose();

        Assert.Equal(new byte[32], key);
        Assert.NotEqual(keyClone, key);
    }

    [Fact]
    public void Dispose_ThenEncrypt_Throws()
    {
        var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt("hello"u8.ToArray(), new byte[33]));
    }

    [Fact]
    public void SequentialOperations_ReuseTheOneAesGcmInstance()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var encrypted = new byte[11 + 28];
        var decrypted = new byte[11];

        for (var i = 0; i < 50; i++)
        {
            cipher.Encrypt("hello world"u8.ToArray(), encrypted);
            cipher.Decrypt(encrypted, decrypted);
        }

        Assert.Equal(1, cipher.InstanceCount);
        Assert.Equal(1, cipher.IdleInstanceCount);
    }

    [Fact]
    public void Rent_WhenNoInstanceIsIdle_BuildsAnotherAndReturnPoolsIt()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));

        var first = cipher.Rent();
        var second = cipher.Rent();

        Assert.NotSame(first, second);
        Assert.Equal(2, cipher.InstanceCount);
        Assert.Equal(0, cipher.IdleInstanceCount);

        cipher.Return(first);
        cipher.Return(second);

        Assert.Equal(2, cipher.IdleInstanceCount);
    }

    [Fact]
    public async Task ConcurrentOperations_EachUseTheirOwnInstance_AndEveryResultRoundTripsUnderItsOwnNonce()
    {
        const int workers = 8;
        const int perWorker = 500;
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var nonces = new ConcurrentDictionary<string, byte>();
        using var start = new ManualResetEventSlim();

        var tasks = Enumerable.Range(0, workers).Select(worker => Task.Run(() =>
        {
            start.Wait();
            var encrypted = new byte[4 + 28];
            var decrypted = new byte[4];
            for (var i = 0; i < perWorker; i++)
            {
                var value = worker * perWorker + i;
                var plaintext = BitConverter.GetBytes(value);
                var aad = BitConverter.GetBytes(worker);

                cipher.Encrypt(plaintext, aad, encrypted);
                Assert.True(nonces.TryAdd(Convert.ToHexString(encrypted.AsSpan(0, 12)), 0), "nonce repeated");

                cipher.Decrypt(encrypted, aad, decrypted);
                Assert.Equal(value, BitConverter.ToInt32(decrypted));
            }
        })).ToArray();

        start.Set();
        await Task.WhenAll(tasks);

        Assert.Equal(workers * perWorker, nonces.Count);
        Assert.InRange(cipher.InstanceCount, 1, workers);
        Assert.Equal(cipher.InstanceCount, cipher.IdleInstanceCount);
    }

    [Fact]
    public void Dispose_WhileAnInstanceIsRented_LetsThatOperationFinish_ThenReleasesItOnReturn()
    {
        var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
        var rented = cipher.Rent();

        cipher.Dispose();

        // The rented instance is untouched by Dispose, so the operation holding it completes.
        var nonce = new byte[12];
        var ciphertext = new byte[4];
        var tag = new byte[16];
        rented.Encrypt(nonce, new byte[4], ciphertext, tag);

        cipher.Return(rented);

        Assert.Equal(0, cipher.IdleInstanceCount);
        Assert.Throws<ObjectDisposedException>(() => rented.Encrypt(nonce, new byte[4], ciphertext, tag));
    }

    [Fact]
    public void Dispose_Twice_IsSafe()
    {
        var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));

        cipher.Dispose();
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.Rent());
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuard.Diagnostics.HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging;
        HkdfGuard.Diagnostics.HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = true;
        try
        {
            using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32));
            var plaintext = "hello world"u8.ToArray();
            var encrypted = new byte[plaintext.Length + 28];
            var written = cipher.Encrypt((byte[])plaintext.Clone(), "aad"u8, encrypted);

            var decrypted = new byte[plaintext.Length];
            cipher.Decrypt(encrypted.AsSpan(0, written), "aad"u8, decrypted);

            Assert.Equal(plaintext, decrypted);
        }
        finally
        {
            HkdfGuard.Diagnostics.HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = original;
        }
    }
}
