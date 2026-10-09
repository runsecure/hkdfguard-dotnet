namespace HkdfGuard.Diagnostics;

/// <summary>
/// Attribute/tag keys shared across every component's spans, events, and metrics - lowercase,
/// dot-separated (OpenTelemetry semantic-convention style), so the same keys translate identically
/// into a Java/Node/Python/Go port's own OTel SDK.
/// </summary>
public static class AttributeNames
{
    public const string Name = "hkdfguard.name";
    public const string PlaintextLength = "hkdfguard.plaintext_length";
    public const string CiphertextLength = "hkdfguard.ciphertext_length";
    public const string EncryptedLength = "hkdfguard.encrypted_length";
    public const string AadLength = "hkdfguard.aad_length";
    public const string ValueLength = "hkdfguard.value_length";
    public const string KeyVersion = "hkdfguard.key_version";
    public const string KeyRingBecameCurrent = "hkdfguard.key_ring.became_current";
    public const string OperationName = "hkdfguard.operation.name";
    public const string Result = "hkdfguard.result";
    public const string EncryptionCount = "hkdfguard.encryption_count";
    public const string EncryptionLimit = "hkdfguard.encryption_limit";
    public const string ConsecutiveFailures = "hkdfguard.consecutive_failures";
}
