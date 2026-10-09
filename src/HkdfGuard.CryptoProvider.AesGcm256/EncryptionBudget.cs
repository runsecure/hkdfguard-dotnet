using System.Security.Cryptography;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <summary>
/// Counts how many times one AES-256-GCM key has encrypted. With random 96-bit nonces, NIST SP
/// 800-38D caps a key at 2^32 encryptions; past that the chance of a repeated nonce - which breaks
/// both confidentiality and integrity for everything under the key - is no longer negligible.
/// One instance is shared by every session built on the same key (the key, not the session, is
/// what the limit applies to). Thread-safe.
/// </summary>
internal sealed class EncryptionBudget
{
    /// <summary>
    /// Hard stop: half the NIST limit, because this counter only sees its own process, and every
    /// instance of a deployment sharing a key file draws on the same budget.
    /// </summary>
    public const long DefaultLimit = 1L << 31;

    /// <summary>Where a telemetry warning is raised - one eighth of the limit.</summary>
    public const long DefaultWarningThreshold = 1L << 28;

    private long _count;

    public EncryptionBudget(long warningThreshold = DefaultWarningThreshold, long limit = DefaultLimit)
    {
        if (limit < 1)
            throw new ArgumentOutOfRangeException(nameof(limit), limit, "Limit must be positive.");
        if (warningThreshold < 1 || warningThreshold > limit)
            throw new ArgumentOutOfRangeException(nameof(warningThreshold), warningThreshold, "Warning threshold must be between 1 and the limit.");

        WarningThreshold = warningThreshold;
        Limit = limit;
    }

    public long WarningThreshold { get; }

    public long Limit { get; }

    /// <summary>Encryptions performed so far under this key.</summary>
    public long Count => Volatile.Read(ref _count);

    /// <summary>
    /// Reserves one encryption. Returns true exactly once, for the reservation that reaches
    /// <see cref="WarningThreshold"/>, so the caller can raise a single warning.
    /// </summary>
    /// <exception cref="CryptographicException">The limit has been reached; the key must be rotated.</exception>
    public bool Consume()
    {
        var count = Interlocked.Increment(ref _count);
        if (count > Limit)
        {
            Interlocked.Decrement(ref _count);
            throw new CryptographicException(
                $"This key has reached its AES-GCM encryption limit of {Limit} and must be rotated; decryption still works.");
        }

        return count == WarningThreshold;
    }
}
