namespace HkdfGuard.Abstractions;

/// <summary>
/// Owns one revealed DEK - how it is revealed, refreshed and eventually zeroed - and performs the
/// AEAD encrypt/decrypt with it.
/// <para>
/// <b>Implementations must zero <c>plaintext</c> in every Encrypt</b>, before returning and on every
/// failure path - including when the key is unavailable (suspended or disposed) and the call
/// throws before any encryption happens. IDataEncryptionKey promises its callers exactly this and
/// relies on the provider to keep it. Decrypt never modifies its ciphertext.
/// </para>
/// </summary>
public interface ICryptoProvider : IDisposable, IAsyncDisposable
{
    /// <summary>
    /// Encrypts plaintext under this provider's key.
    /// </summary>
    /// <param name="plaintext">The bytes to protect. Zeroed before this returns or throws.</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Encrypts plaintext under this provider's key, bound to <paramref name="aad"/>.
    /// </summary>
    /// <param name="plaintext">The bytes to protect. Zeroed before this returns or throws.</param>
    /// <param name="aad">The Additional Auth Data for the encrypt operation</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="aad">Additional Auth Data for the decrypt operation</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result);

    /// <summary>
    /// Gets the required length for allocation from the CryptoProvider for encrypted data
    /// </summary>
    /// <param name="length">The required length for an encrypted value</param>
    /// <returns>Number of bytes required in the encrypted array</returns>
    public int GetEncryptedAllocationLength(int length);
    
    /// <summary>
    /// Gets the required length for allocation from the CryptoProvider for decrypted data
    /// </summary>
    /// <param name="length">The length of the encrypted value</param>
    /// <returns>Number of bytes required in the decrypted array; never negative</returns>
    public int GetDecryptedAllocationLength(int length);
}
