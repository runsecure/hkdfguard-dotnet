using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>Builds a real KeyRing around keys a test has already created, for the caches to resolve from.</summary>
internal static class TestRing
{
    /// <summary>A ring holding <paramref name="key"/> as version 1, its current version.</summary>
    public static KeyRing For(IDataEncryptionKey key)
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, key);
        return ring;
    }
}
