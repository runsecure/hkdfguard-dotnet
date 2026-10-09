using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Diagnostics.Test;

public class CacheMetricsAndLoggerTests
{
    [Fact]
    public void CacheMetricsOperations_IsTheCacheOperationsCounterOnTheCacheMeter()
    {
        var counter = CacheMetrics.Operations;

        Assert.Equal(MetricNames.Cache.Operations, counter.Name);
        Assert.Equal("{operation}", counter.Unit);
        Assert.Same(HkdfGuardTelemetry.Cache.Meter, counter.Meter);
    }

    [Fact]
    public void CacheMetricsOperations_ReportsMeasurementsWithTheirTags()
    {
        var measurements = new List<(long Value, object? Result)>();
        using var listener = new MeterListener
        {
            // Matched by name, not by reference: if CacheMetrics isn't initialized yet, creating
            // its counter publishes it into this callback while CacheMetrics.Operations is still null.
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == HkdfGuardTelemetry.Cache.Meter.Name && instrument.Name == MetricNames.Cache.Operations)
                    l.EnableMeasurementEvents(instrument);
            },
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags)
                if (tag.Key == AttributeNames.Result)
                    measurements.Add((value, tag.Value));
        });
        listener.Start();

        CacheMetrics.Operations.Add(1, new KeyValuePair<string, object?>(AttributeNames.Result, "success"));

        Assert.Contains((1L, (object?)"success"), measurements);
    }

    [Fact]
    public void SensitiveOperationLogged_WritesADebugEntryNamingTheOperationAndName()
    {
        var logger = new CapturingLogger();

        logger.SensitiveOperationLogged("hkdfguard.cache.add", "item");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Equal(1, entry.EventId.Id);
        Assert.Equal("hkdfguard.cache.add completed for item.", entry.Message);
    }

    [Fact]
    public void OperationFailed_WritesAnErrorEntryCarryingTheException()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("boom");

        logger.OperationFailed("hkdfguard.cache.add", failure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(2, entry.EventId.Id);
        Assert.Equal("hkdfguard.cache.add failed.", entry.Message);
        Assert.Same(failure, entry.Exception);
    }

    [Fact]
    public void KeyRefreshFailed_WritesAnErrorEntryWithTheCountPolicyAndException()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("KEK unavailable");

        logger.KeyRefreshFailed(2, "fail closed after 3 consecutive failures", failure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(3, entry.EventId.Id);
        Assert.Equal("Background key refresh failed (2 consecutive). Policy: fail closed after 3 consecutive failures.", entry.Message);
        Assert.Same(failure, entry.Exception);
    }

    [Fact]
    public void KeyAccessSuspended_WritesACriticalEntry()
    {
        var logger = new CapturingLogger();

        logger.KeyAccessSuspended(3);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Critical, entry.Level);
        Assert.Equal(4, entry.EventId.Id);
        Assert.StartsWith("Key access suspended after 3 consecutive failed refreshes", entry.Message);
    }

    [Fact]
    public void KeyAccessResumed_WritesAnInformationEntry()
    {
        var logger = new CapturingLogger();

        logger.KeyAccessResumed(4);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(5, entry.EventId.Id);
        Assert.Equal("Key access resumed: a background refresh succeeded after 4 consecutive failures.", entry.Message);
    }

    [Fact]
    public void EphemeralKeyRotated_WritesAnInformationEntryNamingTheNewVersion()
    {
        var logger = new CapturingLogger();

        logger.EphemeralKeyRotated(8);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(6, entry.EventId.Id);
        Assert.Equal("Ephemeral key rotated: version 8 is now current.", entry.Message);
    }

    [Fact]
    public void EphemeralKeyRotationFailed_WritesAnErrorEntryNamingTheVersionStillCurrent()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("KEK unavailable");

        logger.EphemeralKeyRotationFailed(7, failure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal(7, entry.EventId.Id);
        Assert.Equal("Ephemeral key rotation failed; version 7 stays current until the next attempt.", entry.Message);
        Assert.Same(failure, entry.Exception);
    }

    [Fact]
    public void LoggerExtensions_WhenTheLevelIsDisabled_WriteNothing()
    {
        var logger = new CapturingLogger { Enabled = false };

        logger.SensitiveOperationLogged("hkdfguard.cache.add", "item");
        logger.OperationFailed("hkdfguard.cache.add", new InvalidOperationException());
        logger.KeyRefreshFailed(1, "fail open", new InvalidOperationException());
        logger.KeyAccessSuspended(1);
        logger.KeyAccessResumed(1);
        logger.EphemeralKeyRotated(1);
        logger.EphemeralKeyRotationFailed(1, new InvalidOperationException());

        Assert.Empty(logger.Entries);
    }

    private sealed class CapturingLogger : ILogger
    {
        public bool Enabled { get; init; } = true;
        public List<(LogLevel Level, EventId EventId, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => Enabled;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId, formatter(state, exception), exception));
    }
}
