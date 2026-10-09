namespace HkdfGuard.Abstractions;

/// <summary>
/// Read surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
/// IDataEncryptionKey. Names are compared ignoring ASCII case only ("Item" and "ITEM" are the same
/// name; "café" and "CAFÉ" are not), and each value is bound to its name, so a value can only be
/// revealed under the name it was stored for. Decrypt reveals a stored value back into a caller-owned
/// buffer, returning 0 for a missing name rather than throwing. Nothing here ever holds
/// plaintext beyond the duration of a single Decrypt call - only the encrypted bytes are
/// retained internally.
/// </summary>
public interface IProtectedReadOnlyCache
{
    /// <summary>
    /// Decrypts the value stored under name into result.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The span to receive the decrypted plaintext bytes</param>
    /// <returns>Number of bytes written to result, or 0 if no value is stored under name</returns>
    public int Decrypt(string name, Span<byte> result);

    /// <summary>
    /// Decrypts the value stored under name into result as UTF8-decoded characters.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The span to receive the decrypted plaintext characters</param>
    /// <returns>Number of chars written to result, or 0 if no value is stored under name</returns>
    public int Decrypt(string name, Span<char> result);

    /// <summary>
    /// Attempts to compute an upper bound on how many bytes or chars Decrypt will write for
    /// the value stored under name, so a result buffer can be sized without decrypting first.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="maxLength">An upper bound on the decrypted length, when successful</param>
    /// <returns>True if a value is stored under name</returns>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength);
}
