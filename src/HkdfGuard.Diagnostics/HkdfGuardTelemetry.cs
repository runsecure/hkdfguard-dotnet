namespace HkdfGuard.Diagnostics;

/// <summary>
/// One ComponentTelemetry instance per component in the library - the single place every
/// project's ActivitySource/Meter/EnableSensitiveLogging telemetry now lives. Preserves the same
/// flag-sharing split that existed across the six original per-project Diagnostics classes: Root,
/// Cache, DataProtection, and EncryptedConfiguration all share one EnableSensitiveLogging flag
/// (set any of them, all four read the new value); CryptoProviderAesGcm256 and KeyWrapping each
/// keep their own, independent flag.
/// </summary>
public static class HkdfGuardTelemetry
{
    public static ComponentTelemetry Root { get; } = new("HkdfGuard");

    public static ComponentTelemetry Cache { get; } = new("HkdfGuard.Cache", Root);

    public static ComponentTelemetry DataProtection { get; } = new("HkdfGuard.DataEncryptionKey", Root);

    public static ComponentTelemetry EncryptedConfiguration { get; } = new("HkdfGuard.EncryptedConfiguration", Root);

    public static ComponentTelemetry CryptoProviderAesGcm256 { get; } = new("HkdfGuard.CryptoProvider.AesGcm256");

    public static ComponentTelemetry KeyWrapping { get; } = new("HkdfGuard.KeyWrapping.V1");
}
