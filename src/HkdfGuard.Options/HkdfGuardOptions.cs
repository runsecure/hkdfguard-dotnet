namespace HkdfGuard.Options;

/// <summary>
/// Plain-data mirror of the configuration surface KeyRingBuilder itself exposes - ServiceName,
/// CachedKeyExpiry, the refresh-failure policy, registered key files, and registered ephemeral keys. It
/// carries no behavior: the IKeyWrapper, session-provider factory, and IEncryptedFormatProvider a
/// real KeyRing needs still come from the caller via KeyRingBuilder directly - see
/// HkdfGuardOptionsExtensions.ApplyTo, which copies this data onto a KeyRingBuilder the caller
/// finishes and Builds themselves.
/// </summary>
public sealed class HkdfGuardOptions
{
    /// <summary>
    /// The service name identifying this ring's KEK to the native KMS library.
    /// </summary>
    public string? ServiceName { get; set; }

    /// <summary>
    /// How often, in seconds (1-300), each key is re-revealed through the KEK to confirm the KEK is
    /// still available. A revocation check, not a limit on how long the DEK stays in memory: the
    /// same DEK is revealed each time, and it stays in memory until the ring is disposed. Together
    /// with MaxRefreshFailures it sets how quickly a revoked KEK stops a running process - about
    /// MaxRefreshFailures × CachedKeyExpiry.
    /// </summary>
    public int? CachedKeyExpiry { get; set; }

    /// <summary>
    /// How many consecutive failed attempts to re-reveal a key (every CachedKeyExpiry seconds)
    /// are tolerated before that key's provider fails closed - zeroing the key and refusing
    /// every operation until a refresh succeeds. At least 1. Unset keeps KeyRingBuilder's
    /// default (KeyRingBuilder.DefaultMaxRefreshFailures).
    /// </summary>
    public int? MaxRefreshFailures { get; set; }

    /// <summary>
    /// True opts out of failing closed: the last good key stays in use no matter how many
    /// refreshes fail, so revoking the KEK never stops a running process. Can't be combined with
    /// MaxRefreshFailures.
    /// </summary>
    public bool FailOpenOnRefreshFailure { get; set; }

    /// <summary>
    /// How many hours between scheduled ephemeral key rotations - each adds a fresh ephemeral key
    /// as the ring's new current version. 1 to <see cref="MaxEphemeralKeyRotationHours"/>. Unset keeps
    /// KeyRingBuilder's default of 24 hours. Applies only when EphemeralKeys is not empty. Can't be
    /// combined with DisableEphemeralKeyRotation.
    /// </summary>
    public int? EphemeralKeyRotationHours { get; set; }

    /// <summary>
    /// True turns scheduled ephemeral key rotation off: the ephemeral key built at startup stays
    /// current until the process restarts.
    /// </summary>
    public bool DisableEphemeralKeyRotation { get; set; }

    /// <summary>Largest EphemeralKeyRotationHours - the longest period a timer supports, in whole hours.</summary>
    public const int MaxEphemeralKeyRotationHours = 1193;

    /// <summary>
    /// How many hours a superseded ephemeral key stays registered for decryption after a rotation
    /// replaces it, before the ring disposes and removes it. At least 1. Unset keeps
    /// KeyRingBuilder's default of 24 hours. Applies only when EphemeralKeys is not empty and
    /// rotation is on.
    /// </summary>
    public int? EphemeralKeyRetentionHours { get; set; }

    /// <summary>
    /// Versions whose wrapped DEK is read from a file on disk.
    /// </summary>
    public List<KeyFileOptions> KeyFiles { get; set; } = [];

    /// <summary>
    /// Versions whose key material is generated fresh in memory on first use and never persisted.
    /// </summary>
    public List<int> EphemeralKeys { get; set; } = [];
}
