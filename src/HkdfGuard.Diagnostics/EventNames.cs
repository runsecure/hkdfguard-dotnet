namespace HkdfGuard.Diagnostics;

/// <summary>
/// Fixed Activity event names. Unlike the operation-specific <see cref="ActivityNames"/>, an
/// event's own name stays constant regardless of which operation raised it - the operation itself
/// is carried as the <see cref="AttributeNames.OperationName"/> attribute instead - so event names
/// stay low-cardinality and stable for dashboards/queries.
/// </summary>
public static class EventNames
{
    public const string SensitiveOperation = "hkdfguard.sensitive_operation";

    /// <summary>
    /// Raised once, on the encrypt span that crosses a key's encryption-count warning threshold -
    /// carries <see cref="AttributeNames.EncryptionCount"/> and <see cref="AttributeNames.EncryptionLimit"/>.
    /// </summary>
    public const string EncryptionBudgetWarning = "hkdfguard.encryption_budget_warning";

    /// <summary>
    /// Raised on the background-refresh span whose failure reached the configured consecutive-
    /// failure limit: the provider has disposed its sessions (zeroing the DEK) and suspended
    /// Encrypt/Decrypt until a refresh succeeds. Carries <see cref="AttributeNames.ConsecutiveFailures"/>.
    /// </summary>
    public const string KeyAccessSuspended = "hkdfguard.key_access_suspended";
}
