using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Options;

/// <summary>
/// Copies a validated HkdfGuardOptions instance onto a KeyRingBuilder - ServiceName,
/// CachedKeyExpiry, MaxRefreshFailures/FailOpenOnRefreshFailure, the ephemeral key rotation schedule, every registered KeyFile, and every registered
/// EphemeralKey. The caller still supplies WithKeyWrapper/WithCryptoProviderFactory/
/// WithFormatProvider and calls Build() themselves - those are behavior, not something
/// HkdfGuardOptions can carry as data.
/// </summary>
public static class HkdfGuardOptionsExtensions
{
    public static KeyRingBuilder ApplyTo(this HkdfGuardOptions options, KeyRingBuilder builder)
    {
        if (options.ServiceName is not null)
            builder.WithServiceName(options.ServiceName);

        if (options.CachedKeyExpiry is { } cachedKeyExpiry)
            builder.WithCachedKeyExpiry(cachedKeyExpiry);

        if (options.MaxRefreshFailures is { } maxRefreshFailures)
            builder.WithMaxRefreshFailures(maxRefreshFailures);

        if (options.FailOpenOnRefreshFailure)
            builder.WithFailOpenOnRefreshFailure();

        if (options.EphemeralKeyRotationHours is { } rotationHours)
            builder.WithEphemeralKeyRotation(TimeSpan.FromHours(rotationHours));

        if (options.DisableEphemeralKeyRotation)
            builder.WithoutEphemeralKeyRotation();

        if (options.EphemeralKeyRetentionHours is { } retentionHours)
            builder.WithEphemeralKeyRetention(TimeSpan.FromHours(retentionHours));

        foreach (var keyFile in options.KeyFiles)
            builder.WithKeyFile(keyFile.Version, keyFile.Path);

        foreach (var version in options.EphemeralKeys)
            builder.WithEphemeralKey(version);

        return builder;
    }
}
