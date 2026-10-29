namespace HkdfGuard.Abstractions;

/// <summary>
/// Read surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
/// IDataEncryptionKey. Names are compared ignoring ASCII case only ("Item" and "ITEM" are the same
/// name; "café" and "CAFÉ" are not), and each value is bound to its name, so a value can only be
/// revealed under the name it was stored for. Decrypt reveals a stored value back into a caller-owned
/// buffer, returning 0 for a missing name rather than throwing. Nothing here ever holds
/// plaintext beyond the duration of a single Decrypt call - only the encrypted bytes are
/// retained internally.
/// <para>
/// A cache that may have to fetch a value over the network on a miss (a remote secret store) does
/// that I/O asynchronously in <see cref="DecryptAsync(string, Memory{byte}, CancellationToken)"/>,
/// <see cref="DecryptAsync(string, Memory{char}, CancellationToken)"/> and
/// <see cref="GetMaxDecryptedLengthAsync"/>, where the synchronous members block the calling thread
/// until it completes. Their default implementations call the synchronous members, which is all an
/// in-memory cache needs. An async method can't take a Span, so they write into a Memory instead:
/// pass one over a pinned array (ArrayUtility.AllocatePinned), never a pooled one, and zero it once
/// the value is used, as with any buffer holding plaintext.
/// </para>
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

    /// <summary>
    /// Decrypts the value stored under name into result, as <see cref="Decrypt(string, Span{byte})"/>
    /// does, fetching it asynchronously first if the cache must.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The memory to receive the decrypted plaintext bytes; best over a pinned array</param>
    /// <param name="cancellationToken">Cancels waiting for a fetch</param>
    /// <returns>Number of bytes written to result, or 0 if no value is stored under name</returns>
    public ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Decrypt(name, result.Span));
    }

    /// <summary>
    /// Decrypts the value stored under name into result as UTF8-decoded characters, as
    /// <see cref="Decrypt(string, Span{char})"/> does, fetching it asynchronously first if the cache must.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="result">The memory to receive the decrypted plaintext characters; best over a pinned array</param>
    /// <param name="cancellationToken">Cancels waiting for a fetch</param>
    /// <returns>Number of chars written to result, or 0 if no value is stored under name</returns>
    public ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Decrypt(name, result.Span));
    }

    /// <summary>
    /// An upper bound on how many bytes or chars Decrypt will write for the value stored under name,
    /// as <see cref="TryGetMaxDecryptedLength"/> computes it, fetching the value asynchronously first
    /// if the cache must.
    /// </summary>
    /// <param name="name">The name the value was stored under</param>
    /// <param name="cancellationToken">Cancels waiting for a fetch</param>
    /// <returns>The upper bound, or 0 if no value is stored under name (a stored value is never empty)</returns>
    public ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(TryGetMaxDecryptedLength(name, out var maxLength) ? maxLength : 0);
    }
}
