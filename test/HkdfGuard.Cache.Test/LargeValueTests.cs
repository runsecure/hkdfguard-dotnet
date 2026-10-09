using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>
/// ProtectedCacheBase's plaintext scratch buffers go on the stack up to ArrayUtility.MaxStackBytes
/// and on the pinned heap past it; both paths must round-trip, and the caller's chars are still
/// zeroed.
/// </summary>
public class LargeValueTests
{
    // 15,000 UTF-8 bytes, mixing 1-, 2- and 3-byte characters.
    private static readonly string LargeSecret = string.Concat(Enumerable.Repeat("é-秘密-", 1500));

    private static async Task<ProtectedCache> CreateCacheAsync()
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))));

    [Fact]
    public async Task AddChars_AndDecryptChars_PastTheStackLimit_RoundTrip_AndZeroTheCallersChars()
    {
        Assert.True(Encoding.UTF8.GetByteCount(LargeSecret) > ArrayUtility.MaxStackBytes);
        var cache = await CreateCacheAsync();
        var input = LargeSecret.ToCharArray();

        cache.Add("big", input);

        Assert.All(input, c => Assert.Equal('\0', c));
        Assert.True(cache.TryGetMaxDecryptedLength("big", out var max));
        var result = new char[max];
        var written = cache.Decrypt("big", result);
        Assert.Equal(LargeSecret, new string(result, 0, written));
    }

    [Fact]
    public async Task AddChars_AtTheStackLimit_RoundTrips()
    {
        var cache = await CreateCacheAsync();
        var value = new string('x', ArrayUtility.MaxStackBytes);

        cache.Add("edge", value.ToCharArray());

        var result = new char[ArrayUtility.MaxStackBytes + 64];
        var written = cache.Decrypt("edge", result);
        Assert.Equal(value, new string(result, 0, written));
    }
}
