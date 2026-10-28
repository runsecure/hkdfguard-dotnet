using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.Cache.HashiCorpVault.Test.TestHelpers;

/// <summary>Builds a real KeyRing over real AES-GCM for the cache to encrypt fetched secrets under.</summary>
internal static class TestRing
{
    /// <summary>A ring holding one fresh key as version 1, its current version.</summary>
    public static async Task<KeyRing> CreateAsync()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await NewKeyAsync());
        return ring;
    }

    public static async Task<HkdfGuard.DataEncryptionKey.DataEncryptionKey> NewKeyAsync()
        => new(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));
}
