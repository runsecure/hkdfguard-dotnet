namespace HkdfGuard.Diagnostics;

/// <summary>
/// Span/operation names, one nested class per component - lowercase, dot-separated
/// (OpenTelemetry semantic-convention style: <c>hkdfguard.&lt;component&gt;.&lt;operation&gt;</c>),
/// so the same names translate identically into a Java/Node/Python/Go port's own OTel SDK.
/// </summary>
public static class ActivityNames
{
    public static class Cache
    {
        public const string Add = "hkdfguard.cache.add";
        public const string AddOrUpdate = "hkdfguard.cache.add_or_update";
        public const string Decrypt = "hkdfguard.cache.decrypt";
    }

    public static class DataProtection
    {
        public const string ProtectorEncrypt = "hkdfguard.data_protection.protector.encrypt";
        public const string ProtectorDecrypt = "hkdfguard.data_protection.protector.decrypt";
        public const string KeyWrappedKeyEncrypt = "hkdfguard.data_protection.key_wrapped_key.encrypt";
        public const string KeyWrappedKeyDecrypt = "hkdfguard.data_protection.key_wrapped_key.decrypt";
        public const string EphemeralKeyInitialize = "hkdfguard.data_protection.ephemeral_key.initialize";
        public const string KeyRingAdd = "hkdfguard.data_protection.key_ring.add";
        public const string KeyRingGet = "hkdfguard.data_protection.key_ring.get";
        public const string KeyRingGetCurrent = "hkdfguard.data_protection.key_ring.get_current";
        public const string KeyRingRotateEphemeral = "hkdfguard.data_protection.key_ring.rotate_ephemeral";
        public const string FormatProviderFormat = "hkdfguard.data_protection.format.format";
        public const string FormatProviderParse = "hkdfguard.data_protection.format.parse";
        public const string FormatProviderGetMaxDecryptedLength = "hkdfguard.data_protection.format.get_max_decrypted_length";
    }

    public static class CryptoProviderAesGcm256
    {
        public const string Encrypt = "hkdfguard.crypto_provider_aes_gcm256.encrypt";
        public const string Decrypt = "hkdfguard.crypto_provider_aes_gcm256.decrypt";
        public const string BackgroundRefresh = "hkdfguard.crypto_provider_aes_gcm256.background_refresh";
    }

    public static class EncryptedConfiguration
    {
        public const string Decrypt = "hkdfguard.encrypted_configuration.decrypt";
    }
}
