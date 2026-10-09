using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>
/// With real AES-GCM: every cache entry is bound to its name, so a ciphertext under any other name
/// fails authentication instead of decrypting as that name's value.
/// </summary>
public class NameBindingTests
{
    private static async Task<PopulatingCache> CreateCacheAsync()
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))));

    [Fact]
    public async Task ACiphertextCopiedUnderAnotherName_FailsAuthentication_ThroughBothOverloads()
    {
        var cache = await CreateCacheAsync();
        cache.Seed("ConnectionStrings:Admin", "admin-password".ToCharArray());
        cache.Seed("ConnectionStrings:Reporting", "reporting-password".ToCharArray());

        cache.CopyEntry("ConnectionStrings:Admin", "ConnectionStrings:Reporting");

        Assert.Throws<AuthenticationTagMismatchException>(() => cache.Decrypt("ConnectionStrings:Reporting", new byte[64]));
        Assert.Throws<AuthenticationTagMismatchException>(() => cache.Decrypt("ConnectionStrings:Reporting", new char[64].AsSpan()));
    }

    [Fact]
    public async Task TheOriginalEntry_StillDecrypts()
    {
        var cache = await CreateCacheAsync();
        cache.Seed("ConnectionStrings:Admin", "admin-password".ToCharArray());
        cache.CopyEntry("ConnectionStrings:Admin", "ConnectionStrings:Reporting");

        var result = new byte[64];
        var written = cache.Decrypt("connectionstrings:ADMIN", result);

        Assert.Equal("admin-password", Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task ProtectedCache_AsciiCaseVariantsShareAnEntry_NonAsciiCaseVariantsDoNot()
    {
        var cache = new ProtectedCache(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))));

        cache.Add("Café", "value"u8.ToArray());

        Assert.Equal(5, cache.Decrypt("CAFé", new byte[16]));
        Assert.Equal(0, cache.Decrypt("CAFÉ", new byte[16]));

        // A distinct name, so adding under it succeeds rather than reporting a duplicate.
        cache.Add("CAFÉ", "other"u8.ToArray());
        Assert.Equal(5, cache.Decrypt("cafÉ", new byte[16]));
    }
}
