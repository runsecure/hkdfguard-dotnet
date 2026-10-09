using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>
/// With a real KeyRing and real AES-GCM: the cache encrypts under the ring's current key, so it
/// follows rotation, and every entry keeps decrypting under the key it was stored with.
/// </summary>
public class KeyRingRotationTests
{
    private static async Task<HkdfGuard.DataEncryptionKey.DataEncryptionKey> NewKeyAsync()
        => new(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));

    private static string DecryptString(PopulatingCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task ValuesStoredBeforeAndAfterARotation_UseTheirOwnKeys_AndAllDecrypt()
    {
        await using var ring = TestRing.For(await NewKeyAsync());
        var cache = new PopulatingCache(ring);

        cache.Seed("before", "stored under v1".ToCharArray());
        ring.Add(2, await NewKeyAsync()); // what scheduled ephemeral rotation does
        cache.Seed("after", "stored under v2".ToCharArray());

        Assert.Equal(1, cache.VersionOf("before"));
        Assert.Equal(2, cache.VersionOf("after"));
        Assert.Equal("stored under v1", DecryptString(cache, "before"));
        Assert.Equal("stored under v2", DecryptString(cache, "after"));
    }

    [Fact]
    public async Task AddOrUpdate_AfterARotation_ReEncryptsUnderTheNewKey()
    {
        await using var ring = TestRing.For(await NewKeyAsync());
        var cache = new ProtectedCache(ring);
        cache.AddOrUpdate("item", "first"u8.ToArray());

        ring.Add(2, await NewKeyAsync());
        cache.AddOrUpdate("item", "second"u8.ToArray());

        // Only the new key can decrypt the replacement: v1 alone would fail authentication.
        var result = new byte[16];
        Assert.Equal("second", Encoding.UTF8.GetString(result, 0, cache.Decrypt("item", result)));
    }

    [Fact]
    public async Task AnEntryWhoseVersionWasSwapped_FailsAuthentication()
    {
        await using var ring = TestRing.For(await NewKeyAsync());
        ring.Add(2, await NewKeyAsync());
        var cache = new PopulatingCache(ring);
        cache.Seed("item", "value".ToCharArray());

        cache.RelabelVersion("item", 1); // claims v1, but was encrypted under v2

        Assert.Throws<AuthenticationTagMismatchException>(() => cache.Decrypt("item", new byte[16]));
    }
}
