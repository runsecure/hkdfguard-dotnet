using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// DataProtector's plaintext scratch buffer goes on the stack up to ArrayUtility.MaxStackBytes and
/// on the pinned heap past it; both paths must round-trip.
/// </summary>
public class LargeValueTests
{
    // 15,000 UTF-8 bytes, mixing 1-, 2- and 3-byte characters.
    private static readonly string LargeSecret = string.Concat(Enumerable.Repeat("é-秘密-", 1500));

    [Theory]
    [InlineData(1)]                          // stack
    [InlineData(ArrayUtility.MaxStackBytes)] // largest stack buffer
    [InlineData(-1)]                         // pinned (LargeSecret)
    public async Task Protector_RoundTripsOnBothSidesOfTheStackLimit(int length)
    {
        var plaintext = length < 0 ? LargeSecret : new string('x', length);
        if (length < 0)
            Assert.True(Encoding.UTF8.GetByteCount(plaintext) > ArrayUtility.MaxStackBytes);

        using var ring = new KeyRing(new DefaultFormatProvider(100_000));
        ring.Add(1, new DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60)));
        var protector = ring.CreateProtector("large");

        var formatted = protector.Encrypt(plaintext);
        var result = new char[protector.GetMaxDecryptedLength(formatted)];
        var written = protector.Decrypt(formatted, result);

        Assert.Equal(plaintext, new string(result, 0, written));
    }
}
