using System.Security.Cryptography;
using System.Text;
using HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

/// <summary>
/// Key material that outlives one call sits on the Pinned Object Heap, where the GC never leaves a
/// stale copy behind, and plaintext scratch buffers sit on the stack or, past 4 KiB, on the pinned
/// heap too. A small pinned array reports the oldest GC generation from the moment it is allocated.
/// </summary>
public class PinnedKeyMaterialTests
{
    // 1,500 × (2 + 1 + 6 + 1) = 15,000 UTF-8 bytes: well past the 4 KiB stack limit.
    private static readonly string LargeSecret = string.Concat(Enumerable.Repeat("é-秘密-", 1500));

    private static bool IsPinned(Array array) => GC.GetGeneration(array) == GC.MaxGeneration;

    [Fact]
    public async Task Provider_RevealsEachKeyIntoAPinnedArray_AndKeepsDoingSoAcrossRefreshes()
    {
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        var first = provider.CurrentSession!;

        Assert.True(IsPinned(first.Key));

        await Task.Delay(TimeSpan.FromSeconds(1.3)); // one background refresh
        var refreshed = provider.CurrentSession!;

        Assert.NotSame(first, refreshed);
        Assert.True(IsPinned(refreshed.Key));
    }

    [Fact]
    public void Pipeline_KeyAndItsBase64Form_ArePinned_AndBothAreZeroedOnDispose()
    {
        var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 1);
        _ = protector.GetKeyAsBase64();
        var key = protector.Key;
        var base64 = protector.Base64Buffer!;

        Assert.True(IsPinned(key));
        Assert.True(IsPinned(base64));
        Assert.False(key.All(b => b == 0));

        protector.Dispose();

        Assert.All(key, b => Assert.Equal(0, b));
        Assert.All(base64, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void Pipeline_ValuesPastTheStackLimit_RoundTrip()
    {
        Assert.True(Encoding.UTF8.GetByteCount(LargeSecret) > HkdfGuard.Abstractions.ArrayUtility.MaxStackBytes);
        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(100_000), 1);

        var formatted = protector.Encrypt(LargeSecret, "Big:Secret");
        var result = new char[protector.GetMaxDecryptedLength(formatted)];
        var written = protector.Decrypt(formatted, "Big:Secret", result);

        Assert.Equal(LargeSecret, new string(result, 0, written));
    }
}
