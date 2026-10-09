namespace HkdfGuard.Abstractions;

/// <summary>
/// Read/write surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
/// IDataEncryptionKey. Add/AddOrUpdate protect and store plaintext under a name; the read
/// surface (Decrypt/TryGetMaxDecryptedLength) is inherited from IProtectedReadOnlyCache.
/// Nothing here ever holds plaintext beyond the duration of a single Add/AddOrUpdate call - only
/// the encrypted bytes are retained internally.
/// </summary>
public interface IProtectedCache : IProtectedReadOnlyCache
{
    /// <summary>
    /// Encrypts plaintext and stores it under name.
    /// </summary>
    /// <param name="name">The name to store the encrypted value under</param>
    /// <param name="plaintext">The plaintext to protect - zeroed as a side effect of encrypting it</param>
    /// <exception cref="ArgumentException">A value is already stored under this name</exception>
    public void Add(string name, Span<byte> plaintext);

    /// <summary>
    /// Encrypts plaintext (as UTF8 bytes) and stores it under name.
    /// </summary>
    /// <param name="name">The name to store the encrypted value under</param>
    /// <param name="plaintext">The plaintext to protect - zeroed as a side effect of encrypting it</param>
    /// <exception cref="ArgumentException">A value is already stored under this name</exception>
    public void Add(string name, Span<char> plaintext);

    /// <summary>
    /// Encrypts plaintext and stores it under name, replacing any value already stored under
    /// that name.
    /// </summary>
    /// <param name="name">The name to store the encrypted value under</param>
    /// <param name="plaintext">The plaintext to protect - zeroed as a side effect of encrypting it</param>
    public void AddOrUpdate(string name, Span<byte> plaintext);

    /// <summary>
    /// Encrypts plaintext (as UTF8 bytes) and stores it under name, replacing any value already
    /// stored under that name.
    /// </summary>
    /// <param name="name">The name to store the encrypted value under</param>
    /// <param name="plaintext">The plaintext to protect - zeroed as a side effect of encrypting it</param>
    public void AddOrUpdate(string name, Span<char> plaintext);
}
