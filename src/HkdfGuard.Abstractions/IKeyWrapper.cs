namespace HkdfGuard.Abstractions;

/// <summary>
/// Protects (WrapAsync) and reveals (UnwrapAsync) an encryption key against a single,
/// implicitly identified KEK (e.g. a native KMS-backed key, identified by service name at
/// construction, or a remote KMS/HSM key). UnwrapAsync takes the wrapped payload as an explicit
/// argument on every call, so one instance can reveal any number of different wrapped keys
/// sharing the same KEK - it holds no wrapped payload of its own. Asynchronous so that
/// network-backed KEKs (e.g. AWS KMS, CloudHSM) can be awaited rather than blocked on; local
/// implementations may complete synchronously.
/// </summary>
public interface IKeyWrapper
{
    /// <summary>
    /// Protects an encryption key
    /// </summary>
    /// <param name="plaintext">The plaintext key to protect</param>
    /// <param name="result">The encrypted key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reveals a previously-wrapped key. Implementations must write the complete key and return
    /// its exact length - consumers reject any other count rather than use a partially-filled
    /// buffer - must fail (never return unauthenticated bytes) when <paramref name="wrapped"/> has
    /// been tampered with, and should zero <paramref name="result"/> on failure.
    /// </summary>
    /// <param name="wrapped">The wrapped key to reveal</param>
    /// <param name="result">The decrypted key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a fresh key and immediately protects it against the same KEK this instance
    /// wraps/reveals against - the plaintext key never crosses this call's return value.
    /// </summary>
    /// <param name="result">The wrapped key</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>Number of bytes written to the result</returns>
    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a key file holding a key this instance wrapped, returning its bytes still wrapped -
    /// ready for <see cref="UnwrapAsync"/>. KeyRingBuilder reads every key file through its key
    /// wrapper, so a wrapper backed by a native KMS can read through that KMS's own checks (the
    /// native library refuses a file another account could have replaced, or one holding what looks
    /// like an unwrapped key). The default reads it with ordinary file I/O
    /// (<see cref="WrappedKeyFile.ReadAsync"/>).
    /// </summary>
    /// <param name="path">The key file's path</param>
    /// <param name="cancellationToken">Cancels the operation</param>
    /// <returns>The wrapped key the file holds</returns>
    /// <exception cref="IOException">The file can't be read, or isn't a wrapped key (an
    /// <see cref="InvalidDataException"/>, or a <see cref="FileNotFoundException"/>)</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read the file, or the key
    /// wrapper doesn't trust where it lives</exception>
    public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => WrappedKeyFile.ReadAsync(path, cancellationToken);
}
