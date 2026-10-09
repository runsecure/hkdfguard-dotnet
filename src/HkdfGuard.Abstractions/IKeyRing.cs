namespace HkdfGuard.Abstractions;

/// <summary>
/// A set of data encryption keys tracked by version, one of which is current. Anything that
/// encrypts asks for the current key on every operation, so it follows rotation automatically;
/// anything that decrypts asks for the exact version the value was encrypted under, so values
/// encrypted before a rotation still decrypt. Implemented by HkdfGuard.DataEncryptionKey.KeyRing;
/// defined here so components below that project, such as the protected caches, can depend on it.
/// </summary>
public interface IKeyRing
{
    /// <summary>The version new values are encrypted under - the highest one registered.</summary>
    /// <exception cref="InvalidOperationException">No key has been registered yet</exception>
    public int CurrentVersion { get; }

    /// <summary>The current version together with its key, read atomically.</summary>
    /// <exception cref="InvalidOperationException">No key has been registered yet</exception>
    public (int Version, IDataEncryptionKey Key) GetCurrent();

    /// <summary>The key registered for <paramref name="version"/>.</summary>
    /// <exception cref="KeyNotFoundException">No key is registered for this version</exception>
    public IDataEncryptionKey Get(int version);

    /// <summary>The key registered for <paramref name="version"/>, without throwing on a miss.</summary>
    public bool TryGet(int version, out IDataEncryptionKey? key);
}
