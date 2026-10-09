using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

/// <summary>
/// ICryptoProvider's contract, which IDataEncryptionKey passes on to its callers: Encrypt zeroes
/// the caller's plaintext before it returns, and on every path where it throws - including when
/// no key is available to encrypt with at all.
/// </summary>
public class PlaintextZeroingContractTests
{
    private static byte[] Secret() => "top secret"u8.ToArray();

    [Fact]
    public async Task Encrypt_ZeroesThePlaintext_OnSuccess()
    {
        using var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);
        var plaintext = Secret();

        provider.Encrypt(plaintext, new byte[provider.GetEncryptedAllocationLength(plaintext.Length)]);

        Assert.All(plaintext, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Encrypt_ZeroesThePlaintext_WhenEncryptionFails()
    {
        using var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);
        var plaintext = Secret();

        Assert.Throws<ArgumentException>(() => provider.Encrypt(plaintext, new byte[1])); // result too small

        Assert.All(plaintext, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Encrypt_ZeroesThePlaintext_WhenKeyAccessIsSuspended()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: 1);
        wrapper.ThrowOnDecrypt = new CryptographicException("KEK revoked");
        await Task.Delay(TimeSpan.FromSeconds(1.5));
        Assert.True(provider.KeyAccessSuspended);
        var plaintext = Secret();

        Assert.Throws<CryptographicException>(() => provider.Encrypt(plaintext, new byte[64]));

        Assert.All(plaintext, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Encrypt_ZeroesThePlaintext_AfterDispose()
    {
        var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);
        await provider.DisposeAsync();
        var plaintext = Secret();

        Assert.Throws<ObjectDisposedException>(() => provider.Encrypt(plaintext, "aad"u8, new byte[64]));

        Assert.All(plaintext, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task DataEncryptionKey_PassesTheContractThrough()
    {
        using var key = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(
            await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60));
        var plaintext = Secret();

        key.Encrypt(plaintext, "aad"u8);

        Assert.All(plaintext, b => Assert.Equal(0, b));
    }
}
