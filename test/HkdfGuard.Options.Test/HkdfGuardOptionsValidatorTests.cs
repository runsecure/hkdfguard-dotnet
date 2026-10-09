using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsValidatorTests
{
    private static HkdfGuardOptions ValidOptions()
        => new()
        {
            ServiceName = "my.service",
            CachedKeyExpiry = 60,
            EphemeralKeys = [1],
        };

    [Theory]
    [InlineData(".service", "can't start with '.'")]
    [InlineData("my..service", "can't contain '..'")]
    [InlineData("my-service", "U+002D")]
    public void Validate_ServiceNameBreakingARule_FailsWithTheReason(string serviceName, string reason)
    {
        var options = ValidOptions();
        options.ServiceName = serviceName;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.StartsWith("ServiceName is invalid") && f.Contains(reason));
    }

    [Fact]
    public void Validate_ServiceNameOverTheLimit_Fails()
    {
        var options = ValidOptions();
        options.ServiceName = new string('a', 129);

        Assert.False(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_ValidOptions_Succeeds()
    {
        var result = new HkdfGuardOptionsValidator().Validate(null, ValidOptions());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_MissingServiceName_Fails(string? serviceName)
    {
        var options = ValidOptions();
        options.ServiceName = serviceName;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ServiceName"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(301)]
    public void Validate_CachedKeyExpiryOutOfRange_Fails(int cachedKeyExpiry)
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = cachedKeyExpiry;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("CachedKeyExpiry"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(300)]
    public void Validate_CachedKeyExpiryWithinRange_Succeeds(int cachedKeyExpiry)
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = cachedKeyExpiry;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_CachedKeyExpiryUnset_Succeeds()
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = null;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_OptionsWithNoRotationSetting_Succeed()
    {
        // Key rotation is a deployment concern: there is no rotation setting to validate.
        var result = new HkdfGuardOptionsValidator().Validate(null, ValidOptions());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_NoKeyFilesOrEphemeralKeys_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("key file or ephemeral key"));
    }

    [Fact]
    public void Validate_KeyFileWithoutPath_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("missing a path"));
    }

    [Fact]
    public void Validate_DuplicateVersionAcrossKeyFilesAndEphemeralKeys_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [1];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "/tmp/dek.bin" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("more than once"));
    }

    [Fact]
    public void Validate_UniqueVersionsAcrossKeyFilesAndEphemeralKeys_Succeeds()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [2];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "/tmp/dek.bin" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_MaxRefreshFailuresBelowOne_Fails(int maxRefreshFailures)
    {
        var options = ValidOptions();
        options.MaxRefreshFailures = maxRefreshFailures;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("MaxRefreshFailures"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    public void Validate_MaxRefreshFailuresAtLeastOne_Succeeds(int maxRefreshFailures)
    {
        var options = ValidOptions();
        options.MaxRefreshFailures = maxRefreshFailures;

        Assert.True(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_MaxRefreshFailuresUnset_Succeeds()
    {
        var options = ValidOptions();
        options.MaxRefreshFailures = null;

        Assert.True(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(24)]
    [InlineData(HkdfGuardOptions.MaxEphemeralKeyRotationHours)]
    public void Validate_EphemeralKeyRotationHoursInRange_Succeeds(int hours)
    {
        var options = ValidOptions();
        options.EphemeralKeyRotationHours = hours;

        Assert.True(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
        options.ApplyTo(new KeyRingBuilder()); // and the builder accepts every hour the validator does
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(HkdfGuardOptions.MaxEphemeralKeyRotationHours + 1)]
    public void Validate_EphemeralKeyRotationHoursOutOfRange_Fails(int hours)
    {
        var options = ValidOptions();
        options.EphemeralKeyRotationHours = hours;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("EphemeralKeyRotationHours"));
    }

    [Fact]
    public void Validate_DisableEphemeralKeyRotationWithHours_Fails()
    {
        var options = ValidOptions();
        options.DisableEphemeralKeyRotation = true;
        options.EphemeralKeyRotationHours = 12;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("DisableEphemeralKeyRotation"));
    }

    [Fact]
    public void Validate_DisableEphemeralKeyRotationAlone_Succeeds()
    {
        var options = ValidOptions();
        options.DisableEphemeralKeyRotation = true;

        Assert.True(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_FailOpenOnRefreshFailureAlone_Succeeds()
    {
        var options = ValidOptions();
        options.FailOpenOnRefreshFailure = true;

        Assert.True(new HkdfGuardOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_FailOpenOnRefreshFailureWithMaxRefreshFailures_Fails()
    {
        var options = ValidOptions();
        options.FailOpenOnRefreshFailure = true;
        options.MaxRefreshFailures = 3;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("FailOpenOnRefreshFailure"));
    }
}
