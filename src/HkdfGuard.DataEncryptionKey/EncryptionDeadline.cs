namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// A wall-clock point after which a key stops encrypting, and an earlier one from which that is
/// announced. Decryption is never limited. KeyRingBuilder gives every key-file key one, from the
/// file's age, so a key file that is never rotated stops encrypting rather than encrypting without
/// bound: the per-process encryption budget can't see earlier runs of the process.
/// </summary>
public sealed class EncryptionDeadline
{
    /// <summary>From this instant <see cref="OnWarning"/> is called, once.</summary>
    public required DateTimeOffset WarnAt { get; init; }

    /// <summary>From this instant Encrypt throws EncryptionLimitReachedException.</summary>
    public required DateTimeOffset RefuseAt { get; init; }

    /// <summary>The EncryptionLimitReachedException message.</summary>
    public required string Reason { get; init; }

    /// <summary>Called once, the first time the deadline is checked at or after WarnAt but before RefuseAt.</summary>
    public Action? OnWarning { get; init; }

    /// <summary>Called once, the first time the deadline is checked at or after RefuseAt.</summary>
    public Action? OnExpired { get; init; }
}
