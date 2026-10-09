namespace HkdfGuard.Abstractions;

/// <summary>
/// A named, string-level data protector: the name given at construction is used as the
/// Additional Auth Data for every Encrypt/Decrypt, binding a protected value to the purpose it
/// was protected for so it can't be reused under a different one. Encrypt/Decrypt resolve the
/// actual IDataEncryptionKey to use from a KeyRing, rather than holding one key permanently.
/// </summary>
public interface IDataProtector
{
    /// <summary>
    /// Encrypts a plaintext string and formats the result via the configured IEncryptedFormatProvider
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt. Read-only, so it is not zeroed: the caller
    /// owns it and should clear it once done (its UTF-8 copy inside this call is zeroed).</param>
    /// <returns>The formatted, encrypted string</returns>
    public string Encrypt(ReadOnlySpan<char> plaintext);

    /// <summary>
    /// Parses a formatted encrypted string via the configured IEncryptedFormatProvider and
    /// decrypts it directly into result - this never materializes the plaintext as a string.
    /// </summary>
    /// <param name="encrypted">The formatted, encrypted string</param>
    /// <param name="result">The span to receive the decrypted plaintext characters</param>
    /// <returns>Number of chars written to result</returns>
    public int Decrypt(ReadOnlySpan<char> encrypted, Span<char> result);

    /// <summary>
    /// Computes an upper bound on how many chars Decrypt will write for the given formatted
    /// string, so a result buffer can be sized without decrypting first.
    /// </summary>
    /// <param name="encrypted">The formatted, encrypted string</param>
    /// <returns>An upper bound on the decrypted length</returns>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted);
}
