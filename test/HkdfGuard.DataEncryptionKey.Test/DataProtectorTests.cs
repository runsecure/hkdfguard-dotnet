using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// Exercises IDataProtector's failure paths (Protector.DataProtector is internal - reachable only
/// through KeyRing.CreateProtector, matching how it's actually used in practice).
/// </summary>
public class DataProtectorTests
{
    private static async Task<KeyRing> CreateRingWithOneKeyAsync()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60)));
        return ring;
    }

    [Theory]
    [InlineData("HkdfGuard.Cache:")]
    [InlineData("HkdfGuard.Cache:SECRET")]
    public void CreateProtector_RefusesTheCachesReservedPrefix(string name)
    {
        using var ring = new KeyRing(new DefaultFormatProvider());

        var ex = Assert.Throws<ArgumentException>(() => ring.CreateProtector(name));

        Assert.Contains("reserved", ex.Message);
    }

    [Theory]
    [InlineData("hkdfguard.cache:secret")] // a different AAD from any cache entry's (the prefix is never case-folded)
    [InlineData("MyApp.Cache:secret")]
    [InlineData("HkdfGuard.EncryptedConfiguration:ConnectionStrings:Admin")] // shared with ProtectedConfigurationRoot by design
    public void CreateProtector_AcceptsEveryOtherName(string name)
    {
        using var ring = new KeyRing(new DefaultFormatProvider());

        Assert.NotNull(ring.CreateProtector(name));
    }

    [Fact]
    public async Task AProtector_CannotDecryptACacheEntry_BecauseItCanNeverShareItsAad()
    {
        await using var ring = await CreateRingWithOneKeyAsync();
        var cacheAad = HkdfGuard.Abstractions.ProtectedCacheBase.AadFor("secret");
        var entry = ring.Get(1).Encrypt("cached value"u8.ToArray(), cacheAad);

        // The only protector name whose AAD equals the cache entry's is the reserved one.
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes("HkdfGuard.Cache:SECRET"), cacheAad);
        Assert.Throws<ArgumentException>(() => ring.CreateProtector("HkdfGuard.Cache:SECRET"));
        Assert.NotEmpty(entry);
    }

    [Fact]
    public void Encrypt_OnEmptyRing_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var protector = ring.CreateProtector("purpose");

        Assert.Throws<InvalidOperationException>(() => protector.Encrypt("hello".AsSpan()));
    }

    [Fact]
    public async Task Decrypt_WithMalformedInput_ThrowsFormatException()
    {
        var protector = (await CreateRingWithOneKeyAsync()).CreateProtector("purpose");

        Assert.Throws<FormatException>(() => protector.Decrypt("not-a-valid-format".AsSpan(), new char[16]));
    }

    [Fact]
    public async Task Decrypt_ForUnregisteredVersion_ThrowsKeyNotFoundException()
    {
        var protector = (await CreateRingWithOneKeyAsync()).CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        // Claim a version that was never registered in this ring.
        var tampered = formatted.Replace("::v1::", "::v99::");

        Assert.Throws<KeyNotFoundException>(() => protector.Decrypt(tampered.AsSpan(), new char[16]));
    }

    [Fact]
    public async Task EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var _ = new SensitiveLoggingScope(true);

        var protector = (await CreateRingWithOneKeyAsync()).CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        Span<char> result = new char[16];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public async Task Decrypt_WithDifferentProtectorName_ThrowsDueToAadMismatch()
    {
        var ring = await CreateRingWithOneKeyAsync();
        var formatted = ring.CreateProtector("purpose-a").Encrypt("hello".AsSpan());

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            ring.CreateProtector("purpose-b").Decrypt(formatted.AsSpan(), new char[16]));
    }

    [Fact]
    public void Encrypt_WhenTheKeyThrows_PropagatesTheException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new ThrowingKey());

        Assert.Throws<InvalidOperationException>(() => ring.CreateProtector("purpose").Encrypt("hello".AsSpan()));
    }

    // Throws without zeroing its input - DataProtector must zero the UTF8 plaintext itself.
    private sealed class ThrowingKey : HkdfGuard.Abstractions.IDataEncryptionKey
    {
        public byte[] Encrypt(Span<byte> plaintext) => throw new InvalidOperationException("encrypt failed");
        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad) => throw new InvalidOperationException("encrypt failed");
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => throw new NotSupportedException();
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => throw new NotSupportedException();
    }
}
