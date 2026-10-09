namespace HkdfGuard.Abstractions;

/// <summary>
/// An encrypted value together with the key version it was encrypted under - what an
/// IEncryptedFormatProvider formats into, and parses back out of, the stored string.
/// </summary>
public class KeyTrackingValue
{
    /// <summary>The KeyRing version whose key encrypted <see cref="Value"/>.</summary>
    public int KeyVersion { get; init; }

    /// <summary>The ciphertext.</summary>
    public required byte[] Value { get; init; }
}
