using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Options.Test.TestHelpers;

namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsExtensionsTests
{
    [Fact]
    public void ApplyTo_ReturnsSameBuilderForChaining()
    {
        var builder = new KeyRingBuilder();
        var options = new HkdfGuardOptions();

        var returned = options.ApplyTo(builder);

        Assert.Same(builder, returned);
    }

    [Fact]
    public void ApplyTo_SetsServiceNameCachedKeyExpiryAndMaxRefreshFailures()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = "my.service",
            CachedKeyExpiry = 60,
            MaxRefreshFailures = 3,
        };

        var builder = options.ApplyTo(new KeyRingBuilder());

        Assert.Equal("my.service", builder.ServiceName);
        Assert.Equal(60, builder.CachedKeyExpiry);
        Assert.Equal(3, builder.MaxRefreshFailures);
    }

    [Fact]
    public void ApplyTo_UnsetFields_LeavesBuilderDefaultsUntouched()
    {
        var builder = new HkdfGuardOptions().ApplyTo(new KeyRingBuilder());

        Assert.Null(builder.ServiceName);
        Assert.Null(builder.CachedKeyExpiry);
        Assert.Equal(KeyRingBuilder.DefaultMaxRefreshFailures, builder.MaxRefreshFailures);
    }

    [Fact]
    public void ApplyTo_EphemeralKeyRotationHours_SetsTheInterval()
    {
        var builder = new HkdfGuardOptions { EphemeralKeyRotationHours = 6 }.ApplyTo(new KeyRingBuilder());

        Assert.Equal(TimeSpan.FromHours(6), builder.EphemeralKeyRotationInterval);
    }

    [Fact]
    public void ApplyTo_RotationUnset_KeepsTheTwentyFourHourDefault()
    {
        var builder = new HkdfGuardOptions().ApplyTo(new KeyRingBuilder());

        Assert.Equal(TimeSpan.FromHours(24), builder.EphemeralKeyRotationInterval);
    }

    [Fact]
    public void ApplyTo_EphemeralKeyRetentionHours_SetsTheRetention()
    {
        var builder = new HkdfGuardOptions { EphemeralKeyRetentionHours = 48 }.ApplyTo(new KeyRingBuilder());

        Assert.Equal(TimeSpan.FromHours(48), builder.EphemeralKeyRetention);
    }

    [Fact]
    public void ApplyTo_RetentionUnset_KeepsTheTwentyFourHourDefault()
    {
        var builder = new HkdfGuardOptions().ApplyTo(new KeyRingBuilder());

        Assert.Equal(KeyRingBuilder.DefaultEphemeralKeyRetention, builder.EphemeralKeyRetention);
    }

    [Fact]
    public void ApplyTo_DisableEphemeralKeyRotation_TurnsItOff()
    {
        var builder = new HkdfGuardOptions { DisableEphemeralKeyRotation = true }.ApplyTo(new KeyRingBuilder());

        Assert.Null(builder.EphemeralKeyRotationInterval);
    }

    [Fact]
    public void ApplyTo_FailOpenOnRefreshFailure_ClearsTheBuildersPolicy()
    {
        var builder = new HkdfGuardOptions { FailOpenOnRefreshFailure = true }.ApplyTo(new KeyRingBuilder());

        Assert.Null(builder.MaxRefreshFailures);
    }

    [Fact]
    public async Task ApplyTo_WithEphemeralKeys_RegistersEachOnBuild()
    {
        var options = new HkdfGuardOptions { EphemeralKeys = [1, 2] };

        var ring = await options.ApplyTo(new KeyRingBuilder())
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .BuildAsync();

        Assert.Equal(2, ring.CurrentVersion);
    }

    [Fact]
    public async Task ApplyTo_WithKeyFiles_RegistersEachOnBuild()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var options = new HkdfGuardOptions
            {
                KeyFiles = [new KeyFileOptions { Version = 1, Path = path }],
            };

            var ring = await options.ApplyTo(new KeyRingBuilder())
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
                .WithCachedKeyExpiry(60)
                .BuildAsync();

            Assert.Equal(1, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ApplyTo_WithKeyFilesAndEphemeralKeys_HighestVersionBecomesCurrent()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var options = new HkdfGuardOptions
            {
                KeyFiles = [new KeyFileOptions { Version = 1, Path = path }],
                EphemeralKeys = [2],
            };

            var ring = await options.ApplyTo(new KeyRingBuilder())
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
                .WithCachedKeyExpiry(60)
                .BuildAsync();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
