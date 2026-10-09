namespace HkdfGuard.Abstractions;

public interface IEncryptedFormatProvider
{
    public string Format(KeyTrackingValue value);

    public KeyTrackingValue Parse(ReadOnlySpan<char> encrypted);

    /// <summary>
    /// Computes an upper bound on the decrypted plaintext's length (bytes or chars - safe for
    /// either, since UTF8-decoded char count never exceeds byte count) from the Base64 payload's
    /// length alone, without decoding it. AEAD ciphertext is always at least as long as the
    /// plaintext it encloses, so the actual decrypted length is this value or less - always safe
    /// to size a result buffer to what this returns.
    /// </summary>
    /// <param name="encrypted">The formatted, encrypted string</param>
    /// <returns>An upper bound on the decrypted length</returns>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted);
}
