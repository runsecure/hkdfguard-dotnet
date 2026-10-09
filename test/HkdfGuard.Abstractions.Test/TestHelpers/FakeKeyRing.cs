namespace HkdfGuard.Abstractions.Test.TestHelpers;

/// <summary>
/// A minimal IKeyRing over fixed keys, for testing ProtectedCacheBase without the real KeyRing
/// (which lives in a project above Abstractions). The highest version added is current.
/// </summary>
internal sealed class FakeKeyRing : IKeyRing
{
    private readonly Dictionary<int, IDataEncryptionKey> _keys = [];

    public FakeKeyRing(IDataEncryptionKey key, int version = 1) => Add(version, key);

    public void Add(int version, IDataEncryptionKey key)
    {
        _keys.Add(version, key);
        CurrentVersion = _keys.Keys.Max();
    }

    public void Remove(int version) => _keys.Remove(version);

    public int CurrentVersion { get; private set; }

    public (int Version, IDataEncryptionKey Key) GetCurrent() => (CurrentVersion, _keys[CurrentVersion]);

    public IDataEncryptionKey Get(int version)
        => _keys.TryGetValue(version, out var key) ? key : throw new KeyNotFoundException($"No key is registered for version {version}.");

    public bool TryGet(int version, out IDataEncryptionKey? key) => _keys.TryGetValue(version, out key);
}
