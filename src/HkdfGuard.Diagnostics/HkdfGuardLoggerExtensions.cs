using Microsoft.Extensions.Logging;

namespace HkdfGuard.Diagnostics;

/// <summary>
/// Source-generated ILogger extension methods, shared by every component that chooses to accept
/// an optional ILogger (e.g. ProtectedCache's constructor). Mirrors LogSensitiveOperation/
/// RecordException's gating: SensitiveOperationLogged is only worth calling when
/// ComponentTelemetry.EnableSensitiveLogging is set, while OperationFailed is unconditional -
/// failures are always worth logging.
/// </summary>
public static partial class HkdfGuardLoggerExtensions
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "{OperationName} completed for {Name}.")]
    public static partial void SensitiveOperationLogged(this ILogger logger, string operationName, string? name);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error, Message = "{OperationName} failed.")]
    public static partial void OperationFailed(this ILogger logger, string operationName, Exception exception);

    /// <summary>
    /// A background attempt to re-reveal a key through its key wrapper failed - the KEK may have
    /// been revoked or become unreachable. Logged on every failure, whatever the refresh-failure
    /// policy, since under fail-open this is the only sign that the KEK is gone.
    /// </summary>
    [LoggerMessage(EventId = 3, Level = LogLevel.Error,
        Message = "Background key refresh failed ({ConsecutiveFailures} consecutive). Policy: {RefreshFailurePolicy}.")]
    public static partial void KeyRefreshFailed(this ILogger logger, int consecutiveFailures, string refreshFailurePolicy, Exception exception);

    /// <summary>
    /// The refresh-failure limit was reached: the key has been zeroed and every Encrypt/Decrypt
    /// under it throws until a refresh succeeds.
    /// </summary>
    [LoggerMessage(EventId = 4, Level = LogLevel.Critical,
        Message = "Key access suspended after {ConsecutiveFailures} consecutive failed refreshes; the key has been zeroed and every operation under it fails until a refresh succeeds.")]
    public static partial void KeyAccessSuspended(this ILogger logger, int consecutiveFailures);

    /// <summary>A refresh succeeded after key access had been suspended; operations resume.</summary>
    [LoggerMessage(EventId = 5, Level = LogLevel.Information,
        Message = "Key access resumed: a background refresh succeeded after {ConsecutiveFailures} consecutive failures.")]
    public static partial void KeyAccessResumed(this ILogger logger, int consecutiveFailures);

    /// <summary>A scheduled rotation added a fresh ephemeral key, which is now the current version.</summary>
    [LoggerMessage(EventId = 6, Level = LogLevel.Information,
        Message = "Ephemeral key rotated: version {KeyVersion} is now current.")]
    public static partial void EphemeralKeyRotated(this ILogger logger, int keyVersion);

    /// <summary>
    /// A scheduled rotation could not add a new key; the current version stays in use and the next
    /// interval tries again.
    /// </summary>
    [LoggerMessage(EventId = 7, Level = LogLevel.Error,
        Message = "Ephemeral key rotation failed; version {KeyVersion} stays current until the next attempt.")]
    public static partial void EphemeralKeyRotationFailed(this ILogger logger, int keyVersion, Exception exception);

    /// <summary>
    /// A superseded ephemeral key's retention ran out: it has been removed from the ring and
    /// disposed, so values encrypted under it can no longer be decrypted.
    /// </summary>
    [LoggerMessage(EventId = 8, Level = LogLevel.Information,
        Message = "Ephemeral key retired: version {KeyVersion} has been removed and its key zeroed; values encrypted under it no longer decrypt.")]
    public static partial void EphemeralKeyRetired(this ILogger logger, int keyVersion);

    /// <summary>
    /// A key has performed enough encryptions to cross the warning threshold of its AES-GCM
    /// budget; once it reaches the limit it refuses to encrypt, so rotate it before then.
    /// </summary>
    [LoggerMessage(EventId = 10, Level = LogLevel.Warning,
        Message = "This key has performed {EncryptionCount} encryptions of its {EncryptionLimit} AES-GCM limit; rotate it before the limit, when it stops encrypting.")]
    public static partial void EncryptionBudgetWarning(this ILogger logger, long encryptionCount, long encryptionLimit);

    /// <summary>A retired ephemeral key was removed from the ring but disposing it threw.</summary>
    [LoggerMessage(EventId = 9, Level = LogLevel.Error,
        Message = "Ephemeral key version {KeyVersion} was removed from the ring, but disposing it failed.")]
    public static partial void EphemeralKeyRetirementFailed(this ILogger logger, int keyVersion, Exception exception);

    /// <summary>
    /// The current key file has reached 90% of its maximum age (KeyRingBuilder.WithKeyFileMaxAgeDays);
    /// at <paramref name="refuseAt"/> it stops encrypting, so deploy a new key file at a higher
    /// version before then. Logged once per key.
    /// </summary>
    public static void KeyFileAgeWarning(this ILogger logger, int keyVersion, string keyFilePath, DateTimeOffset refuseAt)
        => LogKeyFileAgeWarning(logger, keyFilePath, keyVersion, FormatIsoUtc(refuseAt));

    // RefuseAt is passed preformatted so the message is the same in every culture and every port.
    [LoggerMessage(EventId = 11, EventName = nameof(KeyFileAgeWarning), Level = LogLevel.Warning,
        Message = "Key file '{KeyFilePath}' (version {KeyVersion}) stops encrypting at {RefuseAt}, when it reaches its maximum age; deploy a new key file at a higher version before then.")]
    private static partial void LogKeyFileAgeWarning(ILogger logger, string keyFilePath, int keyVersion, string refuseAt);

    /// <summary>
    /// The current key file has passed its maximum age and no longer encrypts; values under it
    /// still decrypt. Logged once per key.
    /// </summary>
    [LoggerMessage(EventId = 12, Level = LogLevel.Critical,
        Message = "Key file '{KeyFilePath}' (version {KeyVersion}) has passed its maximum age and no longer encrypts; values under it still decrypt. Deploy a new key file at a higher version.")]
    public static partial void KeyFileExpired(this ILogger logger, int keyVersion, string keyFilePath);

    // ISO 8601 UTC with milliseconds ("2027-01-02T00:00:00.000Z"), whatever the current culture.
    private static string FormatIsoUtc(DateTimeOffset value)
        => value.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
