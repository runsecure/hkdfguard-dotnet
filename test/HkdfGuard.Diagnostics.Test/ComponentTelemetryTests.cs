using System.Diagnostics;

namespace HkdfGuard.Diagnostics.Test;

public class ComponentTelemetryTests
{
    public static IEnumerable<object[]> AllComponents =>
    [
        [HkdfGuardTelemetry.Root],
        [HkdfGuardTelemetry.Cache],
        [HkdfGuardTelemetry.DataProtection],
        [HkdfGuardTelemetry.EncryptedConfiguration],
        [HkdfGuardTelemetry.CryptoProviderAesGcm256],
        [HkdfGuardTelemetry.KeyWrapping],
    ];

    [Theory]
    [MemberData(nameof(AllComponents))]
    public void ActivitySourceAndMeter_NamesMatchSourceName(ComponentTelemetry component)
    {
        Assert.Equal(component.SourceName, component.ActivitySource.Name);
        Assert.Equal(component.SourceName, component.Meter.Name);
    }

    // RecordException is static, so there is no per-component case to run.
    [Fact]
    public void RecordException_WithNullActivity_DoesNotThrow()
    {
        var exception = Record.Exception(() => ComponentTelemetry.RecordException(null, new InvalidOperationException("boom")));

        Assert.Null(exception);
    }

    [Theory]
    [MemberData(nameof(AllComponents))]
    public void RecordException_WithRealActivity_RecordsExceptionAndErrorStatus(ComponentTelemetry component)
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == component.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = component.ActivitySource.StartActivity("test-activity");
        var exception = new InvalidOperationException("boom");

        ComponentTelemetry.RecordException(activity, exception);

        Assert.NotNull(activity);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Contains(activity.Events, e => e.Name == "exception");
    }

    [Theory]
    [MemberData(nameof(AllComponents))]
    public void LogSensitiveOperation_WithNullActivity_DoesNotThrow(ComponentTelemetry component)
    {
        var exception = Record.Exception(() => component.LogSensitiveOperation(null, "test-op"));

        Assert.Null(exception);
    }

    [Theory]
    [MemberData(nameof(AllComponents))]
    public void LogSensitiveOperation_WhenDisabled_DoesNotAddEvent(ComponentTelemetry component)
    {
        var original = component.EnableSensitiveLogging;
        try
        {
            component.EnableSensitiveLogging = false;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == component.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = component.ActivitySource.StartActivity("test-activity");
            component.LogSensitiveOperation(activity, "test-op", ("key", "value"));

            Assert.NotNull(activity);
            Assert.Empty(activity.Events);
        }
        finally
        {
            component.EnableSensitiveLogging = original;
        }
    }

    [Theory]
    [MemberData(nameof(AllComponents))]
    public void LogSensitiveOperation_WhenEnabled_AddsFixedNameEventWithOperationAndDetailTags(ComponentTelemetry component)
    {
        var original = component.EnableSensitiveLogging;
        try
        {
            component.EnableSensitiveLogging = true;

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == component.SourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            };
            ActivitySource.AddActivityListener(listener);

            using var activity = component.ActivitySource.StartActivity("test-activity");
            component.LogSensitiveOperation(activity, "test-op", ("hkdfguard.name", "item"));

            Assert.NotNull(activity);
            var loggedEvent = Assert.Single(activity.Events);
            Assert.Equal(EventNames.SensitiveOperation, loggedEvent.Name);
            Assert.Equal("test-op", loggedEvent.Tags.Single(t => t.Key == AttributeNames.OperationName).Value);
            Assert.Equal("item", loggedEvent.Tags.Single(t => t.Key == "hkdfguard.name").Value);
        }
        finally
        {
            component.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void EnableSensitiveLogging_RootSharesFlagWithCacheDataProtectionAndEncryptedConfiguration()
    {
        var original = HkdfGuardTelemetry.Root.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Root.EnableSensitiveLogging = true;
            Assert.True(HkdfGuardTelemetry.Cache.EnableSensitiveLogging);
            Assert.True(HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging);
            Assert.True(HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging);

            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = false;
            Assert.False(HkdfGuardTelemetry.Root.EnableSensitiveLogging);
            Assert.False(HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging);
            Assert.False(HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging);
        }
        finally
        {
            HkdfGuardTelemetry.Root.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void EnableSensitiveLogging_CryptoProviderAesGcm256AndKeyWrapping_AreIndependentFromRootAndEachOther()
    {
        var originalRoot = HkdfGuardTelemetry.Root.EnableSensitiveLogging;
        var originalCryptoProvider = HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging;
        var originalKeyWrapping = HkdfGuardTelemetry.KeyWrapping.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = false;
            HkdfGuardTelemetry.KeyWrapping.EnableSensitiveLogging = false;

            HkdfGuardTelemetry.Root.EnableSensitiveLogging = true;
            Assert.False(HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging);
            Assert.False(HkdfGuardTelemetry.KeyWrapping.EnableSensitiveLogging);

            HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = true;
            Assert.False(HkdfGuardTelemetry.KeyWrapping.EnableSensitiveLogging);
        }
        finally
        {
            HkdfGuardTelemetry.Root.EnableSensitiveLogging = originalRoot;
            HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = originalCryptoProvider;
            HkdfGuardTelemetry.KeyWrapping.EnableSensitiveLogging = originalKeyWrapping;
        }
    }
}
