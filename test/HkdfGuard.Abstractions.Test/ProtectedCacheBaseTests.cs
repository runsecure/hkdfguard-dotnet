using HkdfGuard.Abstractions.Test.TestHelpers;
using System.Text;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Abstractions.Test;

public class ProtectedCacheBaseTests
{
    [Fact]
    public void DecryptBytes_ForAStoredName_RevealsTheValue()
    {
        var cache = new TestCache();
        cache.Store("item", "value"u8.ToArray());

        var result = new byte[16];
        var written = cache.Decrypt("item", result);

        Assert.Equal("value"u8.ToArray(), result[..written]);
    }

    [Fact]
    public void DecryptChars_ForAStoredName_RevealsTheValue()
    {
        var cache = new TestCache();
        cache.StoreChars("item", "héllo".ToCharArray());

        var result = new char[16];
        var written = cache.Decrypt("item", result.AsSpan());

        Assert.Equal("héllo", new string(result, 0, written));
    }

    [Fact]
    public void Decrypt_ForAMissingName_ReturnsZeroForBothOverloads()
    {
        var cache = new TestCache();

        Assert.Equal(0, cache.Decrypt("missing", new byte[16]));
        Assert.Equal(0, cache.Decrypt("missing", new char[16].AsSpan()));
    }

    [Fact]
    public void Names_AreCaseInsensitive()
    {
        var cache = new TestCache();
        cache.Store("Item", "value"u8.ToArray());

        Assert.Equal(5, cache.Decrypt("ITEM", new byte[16]));
    }

    [Fact]
    public void TryGetMaxDecryptedLength_ForAStoredName_ReturnsTheEncryptedLength()
    {
        var cache = new TestCache();
        cache.Store("item", "value"u8.ToArray());

        Assert.True(cache.TryGetMaxDecryptedLength("item", out var maxLength));
        Assert.Equal(5, maxLength);
    }

    [Fact]
    public void TryGetMaxDecryptedLength_ForAMissingName_ReturnsFalseAndZero()
    {
        var cache = new TestCache();

        Assert.False(cache.TryGetMaxDecryptedLength("missing", out var maxLength));
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public void Decrypt_OnAMiss_PopulatesThroughTryPopulate()
    {
        var cache = new TestCache();
        cache.OnTryPopulate = name =>
        {
            cache.Store(name, "fetched"u8.ToArray());
            return true;
        };

        var result = new byte[16];
        var written = cache.Decrypt("remote", result);

        Assert.Equal("fetched"u8.ToArray(), result[..written]);
        Assert.Equal(["remote"], cache.PopulateRequests);
    }

    [Fact]
    public void Decrypt_WhenTryPopulateClaimsSuccessButStoresNothing_ReturnsZero()
    {
        var cache = new TestCache { OnTryPopulate = _ => true };

        Assert.Equal(0, cache.Decrypt("remote", new byte[16]));
        Assert.False(cache.TryGetMaxDecryptedLength("remote", out _));
    }

    [Fact]
    public void Decrypt_OnAHit_DoesNotCallTryPopulate()
    {
        var cache = new TestCache();
        cache.Store("item", "value"u8.ToArray());

        cache.Decrypt("item", new byte[16]);

        Assert.Empty(cache.PopulateRequests);
    }

    [Fact]
    public void EncryptChars_ZeroesTheCallersChars()
    {
        var cache = new TestCache();
        var plaintext = "secret".ToCharArray();

        cache.StoreChars("item", plaintext);

        Assert.All(plaintext, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void Decrypt_WhenTheKeyFails_RethrowsForBothOverloads()
    {
        var cache = new TestCache(new MaskingKey { ThrowOnDecrypt = true });
        cache.Store("item", "value"u8.ToArray());

        Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new char[16].AsSpan()));
    }

    [Fact]
    public void Decrypt_WithSensitiveLoggingEnabled_StillWorksForBothOverloads()
    {
        var original = HkdfGuardTelemetry.Root.EnableSensitiveLogging;
        HkdfGuardTelemetry.Root.EnableSensitiveLogging = true;
        try
        {
            var cache = new TestCache();
            cache.Store("item", "value"u8.ToArray());

            Assert.Equal(5, cache.Decrypt("item", new byte[16]));
            Assert.Equal(5, cache.Decrypt("item", new char[16].AsSpan()));
        }
        finally
        {
            HkdfGuardTelemetry.Root.EnableSensitiveLogging = original;
        }
    }

    // The smallest concrete cache: exposes Encrypt/EncryptChars for storing, and records (and
    // optionally answers) TryPopulate calls - falling back to the base implementation otherwise.
    private sealed class TestCache(IKeyRing keyRing) : ProtectedCacheBase(keyRing)
    {
        public TestCache(IDataEncryptionKey? key = null)
            : this(new FakeKeyRing(key ?? new MaskingKey()))
        {
        }

        public Func<string, bool>? OnTryPopulate { get; set; }
        public List<string> PopulateRequests { get; } = [];

        public void Store(string name, byte[] plaintext) => Data[name] = Encrypt(name, plaintext);

        public void StoreChars(string name, char[] plaintext) => Data[name] = EncryptChars(name, plaintext);

        public void StoreUnderAnotherName(string encryptedFor, string storedAs, byte[] plaintext) => Data[storedAs] = Encrypt(encryptedFor, plaintext);

        public int VersionOf(string name) => Data[name].KeyVersion;

        public static IEqualityComparer<string> Comparer => NameComparer;

        protected override bool TryPopulate(string name)
        {
            PopulateRequests.Add(name);
            return OnTryPopulate?.Invoke(name) ?? base.TryPopulate(name);
        }
    }

    // A reversible stand-in for real AEAD: XORs every byte with a fixed mask, same length out as in.
    private sealed class MaskingKey : IDataEncryptionKey
    {
        private const byte Mask = 0xA5;

        public bool ThrowOnDecrypt { get; init; }

        public List<byte[]> EncryptAads { get; } = [];
        public List<byte[]> DecryptAads { get; } = [];

        public byte[] Encrypt(Span<byte> plaintext) => Encrypt(plaintext, ReadOnlySpan<byte>.Empty);

        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad)
        {
            EncryptAads.Add(aad.ToArray());
            var output = new byte[plaintext.Length];
            for (var i = 0; i < plaintext.Length; i++)
                output[i] = (byte)(plaintext[i] ^ Mask);
            return output;
        }

        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
        {
            DecryptAads.Add(aad.ToArray());
            if (ThrowOnDecrypt)
                throw new InvalidOperationException("decrypt failed");

            for (var i = 0; i < ciphertext.Length; i++)
                result[i] = (byte)(ciphertext[i] ^ Mask);
            return ciphertext.Length;
        }
    }

    [Theory]
    [InlineData(512)]
    [InlineData(513)]
    [InlineData(2 * 1024 * 1024)]
    public void DecryptChars_WithAValueAroundAndWellAboveTheStackLimit_RoundTrips(int length)
    {
        var cache = new TestCache();
        var value = new string('x', length);
        cache.StoreChars("big", value.ToCharArray());

        var result = new char[length];
        var written = cache.Decrypt("big", result.AsSpan());

        Assert.Equal(length, written);
        Assert.Equal(value, new string(result));
    }

    [Fact]
    public void Store_WithAnEmptyValue_IsRejectedForBothOverloads()
    {
        var cache = new TestCache();

        Assert.Throws<ArgumentException>(() => cache.Store("empty", []));
        Assert.Throws<ArgumentException>(() => cache.StoreChars("empty", []));
        Assert.False(cache.TryGetMaxDecryptedLength("empty", out _));
    }

    [Fact]
    public void EveryValue_IsEncryptedAndDecryptedWithItsNamesAad()
    {
        var key = new MaskingKey();
        var cache = new TestCache(key);

        cache.Store("Item", "value"u8.ToArray());
        cache.Decrypt("ITEM", new byte[16]);
        cache.Decrypt("item", new char[16].AsSpan());

        var expected = ProtectedCacheBase.AadFor("Item");
        Assert.Equal(expected, Assert.Single(key.EncryptAads));
        Assert.All(key.DecryptAads, aad => Assert.Equal(expected, aad));
        Assert.Equal(2, key.DecryptAads.Count);
    }

    [Fact]
    public void AadFor_IsThePrefixPlusTheNameWithOnlyAsciiLettersUpperCased()
    {
        // A known vector, for every port to reproduce byte for byte.
        Assert.Equal("HkdfGuard.Cache:API-KEY_1:CAF\u00E9"u8.ToArray(), ProtectedCacheBase.AadFor("api-Key_1:caf\u00E9"));
        Assert.Equal(ProtectedCacheBase.AadFor("item"), ProtectedCacheBase.AadFor("ITEM"));
        Assert.NotEqual(ProtectedCacheBase.AadFor("caf\u00E9"), ProtectedCacheBase.AadFor("CAF\u00C9"));
    }

    [Fact]
    public void AadFor_RejectsANullName_AndInvalidUtf16()
    {
        Assert.Throws<ArgumentNullException>(() => ProtectedCacheBase.AadFor(null!));
        Assert.ThrowsAny<ArgumentException>(() => ProtectedCacheBase.AadFor("bad\uD800name"));
    }

    [Fact]
    public void Store_UnderAnInvalidUtf16Name_Throws_AndStillZeroesThePlaintext()
    {
        var cache = new TestCache();
        var plaintext = "value"u8.ToArray();

        Assert.ThrowsAny<ArgumentException>(() => cache.Store("bad\uD800name", plaintext));

        Assert.All(plaintext, b => Assert.Equal(0, b));
        Assert.False(cache.TryGetMaxDecryptedLength("bad\uD800name", out _));
    }

    [Fact]
    public void AValueStoredUnderADifferentNameThanItWasEncryptedFor_IsDecryptedWithTheLookupNamesAad()
    {
        // The masking key can't fail authentication, so check what a real AEAD would be asked:
        // the AAD of the name looked up, not the one encrypted for - which is what makes it fail.
        var key = new MaskingKey();
        var cache = new TestCache(key);

        cache.StoreUnderAnotherName(encryptedFor: "admin", storedAs: "reporting", "secret"u8.ToArray());
        cache.Decrypt("reporting", new byte[16]);

        Assert.Equal(ProtectedCacheBase.AadFor("admin"), Assert.Single(key.EncryptAads));
        Assert.Equal(ProtectedCacheBase.AadFor("reporting"), Assert.Single(key.DecryptAads));
    }

    [Fact]
    public void NamesLongerThanTheStackAad_StillRoundTripThroughBothOverloads()
    {
        var name = new string('n', 600);
        var cache = new TestCache();

        cache.Store(name, "value"u8.ToArray());

        Assert.Equal(5, cache.Decrypt(name.ToUpperInvariant(), new byte[16]));
        var chars = new char[16];
        Assert.Equal("value", new string(chars, 0, cache.Decrypt(name, chars.AsSpan())));
    }

    [Fact]
    public void NonAsciiCaseVariants_AreDifferentNames()
    {
        var cache = new TestCache();
        cache.Store("caf\u00E9", "value"u8.ToArray());

        Assert.Equal(0, cache.Decrypt("CAF\u00C9", new byte[16]));
        Assert.Equal(5, cache.Decrypt("CAF\u00E9", new byte[16]));
    }

    [Theory]
    [InlineData("item", "ITEM", true)]
    [InlineData("Item-1_x", "iTEM-1_X", true)]
    [InlineData("caf\u00E9", "CAF\u00C9", false)]
    [InlineData("\u017Fecret", "Secret", false)]
    [InlineData("item", "items", false)]
    [InlineData("item", "itex", false)]
    [InlineData("", "", true)]
    public void NameComparer_IgnoresOnlyAsciiCase(string x, string y, bool equal)
    {
        var comparer = TestCache.Comparer;

        Assert.Equal(equal, comparer.Equals(x, y));
        if (equal)
            Assert.Equal(comparer.GetHashCode(x), comparer.GetHashCode(y));
    }

    [Fact]
    public void NameComparer_HandlesNullAndTheSameInstance()
    {
        var comparer = TestCache.Comparer;
        var name = "item";

        Assert.True(comparer.Equals(name, name));
        Assert.True(comparer.Equals(null, null));
        Assert.False(comparer.Equals(name, null));
        Assert.False(comparer.Equals(null, name));
    }

    [Fact]
    public void EachEntry_RecordsTheVersionItWasEncryptedUnder_AndDecryptsWithThatVersionsKey()
    {
        var first = new MaskingKey();
        var second = new MaskingKey();
        var ring = new FakeKeyRing(first, version: 1);
        var cache = new TestCache(ring);

        cache.Store("before", "one"u8.ToArray());
        ring.Add(2, second);                       // the ring rotates
        cache.Store("after", "two"u8.ToArray());

        Assert.Equal(1, cache.VersionOf("before"));
        Assert.Equal(2, cache.VersionOf("after"));
        Assert.Single(first.EncryptAads);
        Assert.Single(second.EncryptAads);

        var result = new byte[8];
        Assert.Equal("one"u8.ToArray(), result[..cache.Decrypt("before", result)]);
        Assert.Equal("two"u8.ToArray(), result[..cache.Decrypt("after", result.AsSpan())]);
        Assert.Single(first.DecryptAads);
        Assert.Single(second.DecryptAads);
    }

    [Fact]
    public void Decrypt_WhenTheEntrysVersionIsNoLongerInTheRing_ThrowsKeyNotFound()
    {
        var ring = new FakeKeyRing(new MaskingKey(), version: 1);
        var cache = new TestCache(ring);
        cache.Store("item", "value"u8.ToArray());
        ring.Add(2, new MaskingKey());
        ring.Remove(1);

        Assert.Throws<KeyNotFoundException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Throws<KeyNotFoundException>(() => cache.Decrypt("item", new char[16].AsSpan()));
    }
}
