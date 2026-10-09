using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.EncryptedConfiguration.Test.TestHelpers;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.EncryptedConfiguration.Test;

/// <summary>
/// ProtectedConfigurationRoot.Decrypt(bytes) decrypts into a char scratch buffer that goes on the
/// stack up to ArrayUtility.MaxStackChars and on the pinned heap past it; both must round-trip.
/// </summary>
public class LargeValueTests
{
    // 15,000 UTF-8 bytes, mixing 1-, 2- and 3-byte characters.
    private static readonly string LargeSecret = string.Concat(Enumerable.Repeat("é-秘密-", 1500));

    [Theory]
    [InlineData("small value")] // stack
    [InlineData(null)]          // pinned (LargeSecret)
    public async Task DecryptBytes_OnBothSidesOfTheStackLimit_RoundTrips(string? plaintext)
    {
        plaintext ??= LargeSecret;
        using var ring = new KeyRing(new DefaultFormatProvider(100_000));
        ring.Add(1, new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60)));
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Big:Secret"] = ring.CreateProtector(ProtectedConfigurationPurpose.For("Big:Secret")).Encrypt(plaintext),
            })
            .Build();
        var root = new ProtectedConfigurationRoot(configuration, ring);

        Assert.True(root.TryGetMaxDecryptedLength("Big:Secret", out var max));
        var result = new byte[max];
        var written = root.Decrypt("Big:Secret", result);

        Assert.Equal(plaintext, Encoding.UTF8.GetString(result, 0, written));
    }
}
