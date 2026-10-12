using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <summary>
/// Counts how many times one AES-256-GCM key has encrypted. With random 96-bit nonces, NIST SP
/// 800-38D caps a key at 2^32 encryptions; past that the chance of a repeated nonce - which breaks
/// both confidentiality and integrity for everything under the key - is no longer negligible.
/// One instance is shared by every session built on the same key (the key, not the session, is
/// what the limit applies to) - and, through <see cref="For"/>, by every provider in this process
/// that reveals that key. Thread-safe.
/// </summary>
internal sealed class EncryptionBudget
{
    // Budgets by key, for the life of the process: one small entry per distinct DEK revealed.
    // Indexed by an HMAC under a key generated for this process, never by the DEK or a plain hash
    // of it - a plain hash would be the same in every process and on every machine, a stable
    // fingerprint of the key sitting in memory.
    private static readonly byte[] RegistryKey = RandomNumberGenerator.GetBytes(32);
    private static readonly ConcurrentDictionary<string, EncryptionBudget> ByKey = new();

    /// <summary>
    /// The budget for <paramref name="key"/>, shared by every provider in this process that
    /// reveals the same DEK - two KeyRings built from one key file draw on one count, not two.
    /// </summary>
    internal static EncryptionBudget For(ReadOnlySpan<byte> key)
    {
        Span<byte> id = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(RegistryKey, key, id);
        return ByKey.GetOrAdd(Convert.ToHexString(id), static _ => new EncryptionBudget());
    }

    /// <summary>
    /// Hard stop: half the NIST limit, because this counter only sees its own process, and every
    /// process of a deployment sharing a key file draws on the same budget. Within one process the
    /// count is shared through <see cref="For"/>; across processes it can't be, so the halving
    /// covers two processes per key file at most - more need more headroom or more frequent
    /// releases.
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
