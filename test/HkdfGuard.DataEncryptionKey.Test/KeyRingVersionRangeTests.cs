using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// Every int is a usable key version. The ring's "no key yet" marker used to be int.MinValue, so a
/// key registered at that version was indistinguishable from an empty ring.
/// </summary>
public class KeyRingVersionRangeTests
{
    private static async Task<DataEncryptionKey> NewKeyAsync()
        => new(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));

    [Theory]
    [InlineData(int.MinValue)]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(int.MaxValue)]
    public async Task AnyIntVersion_BecomesCurrent_AndEncryptsAndDecrypts(int version)
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(version, await NewKeyAsync());

        Assert.Equal(version, ring.CurrentVersion);
        Assert.Equal(version, ring.GetCurrent().Version);

        var protector = ring.CreateProtector("range");
        var formatted = protector.Encrypt("value");
        var result = new char[protector.GetMaxDecryptedLength(formatted)];
        Assert.Equal("value", new string(result, 0, protector.Decrypt(formatted, result)));
    }

    [Fact]
    public async Task MinValue_IsReplacedByAnyHigherVersion_AndNeverReplacesOne()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());

        ring.Add(int.MinValue, await NewKeyAsync());
        ring.Add(5, await NewKeyAsync());
        Assert.Equal(5, ring.CurrentVersion);

        using var other = new KeyRing(new DefaultFormatProvider());
        other.Add(5, await NewKeyAsync());
        other.Add(int.MinValue, await NewKeyAsync());
        Assert.Equal(5, other.CurrentVersion);
    }
}
