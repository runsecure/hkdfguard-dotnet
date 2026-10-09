namespace HkdfGuard.Abstractions;

/// <summary>
/// One data encryption key (DEK): AEAD-encrypts and decrypts byte payloads under it, optionally
/// bound to Additional Authenticated Data.
/// <para>
/// <b>Encrypt consumes its plaintext.</b> The <c>plaintext</c> span is zeroed before Encrypt
/// returns, and also when it throws, so a secret handed in is never left behind in the caller's
/// buffer. Callers that still need the value afterwards must pass a copy. Decrypt never modifies
/// its ciphertext.
/// </para>
/// </summary>
public interface IDataEncryptionKey
{
    /// <summary>
    /// Encrypts plaintext under this key.
    /// </summary>
    /// <param name="plaintext">The bytes to protect. Zeroed before this returns or throws - pass a
    /// copy if you still need them.</param>
    /// <returns>The ciphertext, ready to be stored</returns>
    public byte[] Encrypt(Span<byte> plaintext);

    /// <summary>
    /// Encrypts plaintext under this key, bound to <paramref name="aad"/>.
    /// </summary>
    /// <param name="plaintext">The bytes to protect. Zeroed before this returns or throws - pass a
    /// copy if you still need them.</param>
    /// <param name="aad">Additional Authenticated Data; Decrypt must supply the same bytes</param>
    /// <returns>The ciphertext, ready to be stored</returns>
    public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad);

    /// <summary>
    /// Decrypts and authenticates ciphertext produced by <see cref="Encrypt(Span{byte})"/>.
    /// </summary>
    /// <param name="ciphertext">The ciphertext; not modified</param>
    /// <param name="result">Receives the plaintext. The caller owns it and should zero it once done.</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result);

    /// <summary>
    /// Decrypts and authenticates ciphertext produced by
    /// <see cref="Encrypt(Span{byte}, ReadOnlySpan{byte})"/> with the same <paramref name="aad"/>.
    /// </summary>
    /// <param name="ciphertext">The ciphertext; not modified</param>
    /// <param name="aad">The Additional Authenticated Data it was encrypted with</param>
    /// <param name="result">Receives the plaintext. The caller owns it and should zero it once done.</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result);
}
