namespace HkdfGuard.Abstractions;

/// <summary>
/// Size limits for a wrapped DEK - the bytes a key file holds and an IKeyWrapper produces.
/// </summary>
public static class WrappedKeyLimits
{
    /// <summary>
    /// Largest wrapped DEK, in bytes, this library will read from a key file or let a key wrapper
    /// generate. Today's native payloads are far smaller (156 bytes on macOS); the headroom allows
    /// larger keys for other symmetric algorithms and additional fingerprinting. Raise this one
    /// value to allow bigger payloads: KeyRingBuilder's key-file check and the buffer
    /// ICryptoProviderFactory implementations generate into both follow it.
    /// </summary>
    public const int MaxBytes = 512;
}
