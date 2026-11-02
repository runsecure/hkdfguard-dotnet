using System.Security.Cryptography;

namespace HkdfGuard.Abstractions;

/// <summary>
/// A key has performed as many encryptions as its cipher safely allows; rotate it. Decryption
/// still works. Thrown by DataEncryptionKey.Encrypt once a key file has passed its maximum age
/// (KeyRingBuilder.WithKeyFileMaxAgeDays). A CryptographicException, so code that already catches
/// one around Encrypt keeps catching it.
/// </summary>
public sealed class EncryptionLimitReachedException : CryptographicException
{
    public EncryptionLimitReachedException(string message)
        : base(message)
    {
    }

    public EncryptionLimitReachedException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
