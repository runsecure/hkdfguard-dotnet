using System.Security.Cryptography;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Cache.Test;

/// <summary>ProtectedCacheCollection's asynchronous lookups, each source asked in order with its own DecryptAsync.</summary>
public class ProtectedCacheCollectionAsyncTests
{
    private static async Task<ProtectedCache> CreateCacheAsync()
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))));

    [Fact]
    public async Task DecryptAsync_ReturnsFromTheFirstSourceThatHasIt_ForBothOverloads()
    {
        var first = await CreateCacheAsync();
        var second = await CreateCacheAsync();
        first.Add("item", "from-first"u8.ToArray());
        second.Add("item", "from-second"u8.ToArray());
        second.Add("only-second", "second"u8.ToArray());
        var collection = new ProtectedCacheCollection().Add(first).Add(second);

        var bytes = new byte[32];
        Assert.Equal("from-first"u8.ToArray(), bytes[..await collection.DecryptAsync("item", bytes.AsMemory())]);
        var chars = new char[32];
        Assert.Equal("second", new string(chars, 0, await collection.DecryptAsync("only-second", chars.AsMemory())));
        Assert.True(await collection.GetMaxDecryptedLengthAsync("only-second") >= 6);
    }

    [Fact]
    public async Task DecryptAsync_WithNoSourceHoldingIt_ReturnsZero()
    {
        var collection = new ProtectedCacheCollection().Add(await CreateCacheAsync());

        Assert.Equal(0, await collection.DecryptAsync("missing", new byte[16].AsMemory()));
        Assert.Equal(0, await collection.DecryptAsync("missing", new char[16].AsMemory()));
        Assert.Equal(0, await collection.GetMaxDecryptedLengthAsync("missing"));
        Assert.Equal(0, await new ProtectedCacheCollection().DecryptAsync("missing", new byte[16].AsMemory()));
    }

    [Fact]
    public async Task DecryptAsync_WhenASourceThrows_Rethrows_ForBothOverloads()
    {
        var collection = new ProtectedCacheCollection().Add(new ThrowingReadOnlyCache(new InvalidOperationException("boom")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => collection.DecryptAsync("item", new byte[16].AsMemory()).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => collection.DecryptAsync("item", new char[16].AsMemory()).AsTask());
    }

    [Fact]
    public async Task DecryptAsync_WithSensitiveLoggingEnabled_StillWorks()
    {
        var cache = await CreateCacheAsync();
        cache.Add("item", "value"u8.ToArray());
        var collection = new ProtectedCacheCollection().Add(cache);

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
        try
        {
            Assert.Equal(5, await collection.DecryptAsync("item", new byte[16].AsMemory()));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }
}
