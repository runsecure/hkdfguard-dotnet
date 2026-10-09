using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// A minimal ProtectedCacheBase subclass whose TryPopulate is driven directly by the test - lets
/// tests exercise the base class's cache-miss-then-populate path without depending on any real
/// external source.
/// </summary>
internal sealed class PopulatingCache(IKeyRing keyRing) : ProtectedCacheBase(keyRing)
{
    public int TryPopulateCallCount { get; private set; }
    public Func<string, bool>? OnTryPopulate { get; set; }

    public void Seed(string name, Span<char> plaintext) => Data[name] = EncryptChars(name, plaintext);

    /// <summary>Copies one entry's ciphertext under another name, as a populate bug or tampering would.</summary>
    public void CopyEntry(string from, string to) => Data[to] = Data[from];

    /// <summary>The key version the entry stored under name was encrypted with.</summary>
    public int VersionOf(string name) => Data[name].KeyVersion;

    /// <summary>Rewrites an entry's recorded key version, as tampering would.</summary>
    public void RelabelVersion(string name, int version) => Data[name] = new KeyTrackingValue { KeyVersion = version, Value = Data[name].Value };

    protected override bool TryPopulate(string name)
    {
        TryPopulateCallCount++;
        return OnTryPopulate?.Invoke(name) ?? false;
    }
}
