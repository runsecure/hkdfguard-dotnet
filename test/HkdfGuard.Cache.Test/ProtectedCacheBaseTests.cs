using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Cache.Test;

public class ProtectedCacheBaseTests
{
    private static async Task<PopulatingCache> CreateCacheAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        return new PopulatingCache(TestRing.For(dataProtectionKey));
    }

    [Fact]
    public async Task Decrypt_OnMiss_CallsTryPopulate_AndReturnsPopulatedValue()
    {
        var cache = await CreateCacheAsync();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value".ToCharArray());
            return true;
        };

        var result = new byte[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(1, cache.TryPopulateCallCount);
        Assert.Equal("populated value", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_WhenAlreadyCached_DoesNotCallTryPopulate()
    {
        var cache = await CreateCacheAsync();
        cache.Seed("item", "already cached".ToCharArray());
        cache.OnTryPopulate = _ => throw new InvalidOperationException("should not be called");

        var result = new byte[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(0, cache.TryPopulateCallCount);
        Assert.Equal("already cached", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_WhenTryPopulateReturnsFalse_ReturnsZero()
    {
        var cache = await CreateCacheAsync();
        cache.OnTryPopulate = _ => false;

        var written = cache.Decrypt("item", new byte[32]);

        Assert.Equal(0, written);
        Assert.Equal(1, cache.TryPopulateCallCount);
    }

    [Fact]
    public async Task Decrypt_WhenTryPopulateReturnsTrueButDoesNotActuallyPopulate_ReturnsZero()
    {
        var cache = await CreateCacheAsync();
        cache.OnTryPopulate = _ => true; // lies - never calls Seed

        var written = cache.Decrypt("item", new byte[32]);

        Assert.Equal(0, written);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_OnMiss_CallsTryPopulate()
    {
        var cache = await CreateCacheAsync();
        cache.OnTryPopulate = name =>
        {
            cache.Seed(name, "populated value".ToCharArray());
            return true;
        };

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);

        Assert.True(found);
        Assert.True(maxLength > 0);
        Assert.Equal(1, cache.TryPopulateCallCount);
    }

    [Fact]
    public async Task DefaultTryPopulate_ReturnsFalse_WithoutOverride()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        var cache = new PopulatingCache(TestRing.For(dataProtectionKey)) { OnTryPopulate = null };

        var written = cache.Decrypt("item", new byte[16]);

        Assert.Equal(0, written);
    }
}
