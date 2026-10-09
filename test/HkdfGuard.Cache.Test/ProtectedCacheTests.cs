using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.Test;

public class ProtectedCacheTests
{
    private static async Task<IProtectedCache> CreateCacheAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        return new ProtectedCache(TestRing.For(dataProtectionKey));
    }

    [Fact]
    public async Task AddDecrypt_Bytes_RoundTrips()
    {
        var cache = await CreateCacheAsync();
        var plaintext = "top secret bytes"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("item", plaintext);

        var result = new byte[expected.Length];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task AddDecrypt_Chars_RoundTrips()
    {
        var cache = await CreateCacheAsync();
        const string plaintext = "top secret chars";

        cache.Add("item", plaintext.ToCharArray());

        var result = new char[plaintext.Length];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(plaintext.Length, written);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public async Task AddDecrypt_Chars_HandlesMultiByteUtf8()
    {
        var cache = await CreateCacheAsync();
        const string plaintext = "héllo wörld 日本語";

        cache.Add("item", plaintext.ToCharArray());

        var result = new char[plaintext.Length];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public async Task Add_Bytes_CalledTwiceWithSameName_ThrowsArgumentException()
    {
        var cache = await CreateCacheAsync();

        cache.Add("item", "first"u8.ToArray());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second"u8.ToArray()));
    }

    [Fact]
    public async Task Add_Chars_CalledTwiceWithSameName_ThrowsArgumentException()
    {
        var cache = await CreateCacheAsync();

        cache.Add("item", "first".ToCharArray());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second".ToCharArray()));
    }

    [Fact]
    public async Task Add_Bytes_CalledTwiceWithDifferentCasedName_ThrowsArgumentException()
    {
        var cache = await CreateCacheAsync();

        cache.Add("Item", "first"u8.ToArray());

        Assert.Throws<ArgumentException>(() => cache.Add("ITEM", "second"u8.ToArray()));
    }

    [Fact]
    public async Task Add_Bytes_DoesNotReplacePreviousValueWhenDuplicateNameRejected()
    {
        var cache = await CreateCacheAsync();
        var original = "original"u8.ToArray();
        var expected = (byte[])original.Clone();

        cache.Add("item", original);
        Assert.Throws<ArgumentException>(() => cache.Add("item", "attempted-overwrite"u8.ToArray()));

        var result = new byte[expected.Length];
        var written = cache.Decrypt("item", result);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public async Task AddOrUpdate_Bytes_CalledTwiceWithSameName_ReplacesPreviousValue()
    {
        var cache = await CreateCacheAsync();

        cache.AddOrUpdate("item", "first"u8.ToArray());
        cache.AddOrUpdate("item", "second-value"u8.ToArray());

        cache.TryGetMaxDecryptedLength("item", out var maxLength);
        var result = new byte[maxLength];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal("second-value", Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task AddOrUpdate_Chars_CalledTwiceWithSameName_ReplacesPreviousValue()
    {
        var cache = await CreateCacheAsync();

        cache.AddOrUpdate("item", "first".ToCharArray());
        cache.AddOrUpdate("item", "second-value".ToCharArray());

        var result = new char[32];
        var written = cache.Decrypt("item", result);

        Assert.True(written > 0);
        Assert.Equal("second-value", new string(result, 0, written));
    }

    [Fact]
    public async Task AddOrUpdate_AfterAdd_ReplacesPreviousValueWithoutThrowing()
    {
        var cache = await CreateCacheAsync();

        cache.Add("item", "first"u8.ToArray());
        var exception = Record.Exception(() => cache.AddOrUpdate("item", "second"u8.ToArray()));

        Assert.Null(exception);
    }

    [Fact]
    public async Task NamesAreCaseInsensitive_AcrossAddAndDecrypt()
    {
        var cache = await CreateCacheAsync();
        var plaintext = "value"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("Item-Name", plaintext);

        var result = new byte[expected.Length];
        var written = cache.Decrypt("ITEM-name", result);

        Assert.True(written > 0);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public async Task NamesAreCaseInsensitive_AcrossAddOrUpdate()
    {
        var cache = await CreateCacheAsync();

        cache.AddOrUpdate("Item-Name", "first"u8.ToArray());
        cache.AddOrUpdate("ITEM-name", "second"u8.ToArray());

        cache.TryGetMaxDecryptedLength("item-name", out var maxLength);
        var result = new byte[maxLength];
        var written = cache.Decrypt("item-name", result);

        Assert.Equal("second", Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_Bytes_WithUnknownName_ReturnsZero()
    {
        var cache = await CreateCacheAsync();

        var written = cache.Decrypt("missing", new byte[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public async Task Decrypt_Chars_WithUnknownName_ReturnsZero()
    {
        var cache = await CreateCacheAsync();

        var written = cache.Decrypt("missing", new char[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_WithUnknownName_ReturnsFalse()
    {
        var cache = await CreateCacheAsync();

        var found = cache.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_IsSafeUpperBoundForDecrypt()
    {
        var cache = await CreateCacheAsync();
        var plaintext = "some plaintext value"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        cache.Add("item", plaintext);

        var found = cache.TryGetMaxDecryptedLength("item", out var maxLength);
        Assert.True(found);

        var result = new byte[maxLength];
        var written = cache.Decrypt("item", result);

        Assert.True(maxLength >= written);
        Assert.Equal(expected, result[..written]);
    }

    [Fact]
    public async Task AddDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;

            var cache = await CreateCacheAsync();
            var plaintext = "top secret"u8.ToArray();
            var expected = (byte[])plaintext.Clone();

            cache.Add("item", plaintext);
            var result = new byte[expected.Length];
            var written = cache.Decrypt("item", result);

            Assert.True(written > 0);
            Assert.Equal(expected, result[..written]);
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task AddOrUpdateDecrypt_Chars_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;

            var cache = await CreateCacheAsync();
            const string plaintext = "top secret chars";

            cache.AddOrUpdate("item", plaintext.ToCharArray());
            var result = new char[plaintext.Length];
            var written = cache.Decrypt("item", result);

            Assert.True(written > 0);
            Assert.Equal(plaintext, new string(result, 0, written));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task Add_Chars_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;

            var cache = await CreateCacheAsync();
            const string plaintext = "top secret chars";

            cache.Add("item", plaintext.ToCharArray());
            var result = new char[plaintext.Length];
            var written = cache.Decrypt("item", result);

            Assert.True(written > 0);
            Assert.Equal(plaintext, new string(result, 0, written));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task AddOrUpdate_Bytes_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;

            var cache = await CreateCacheAsync();
            var plaintext = "top secret"u8.ToArray();
            var expected = (byte[])plaintext.Clone();

            cache.AddOrUpdate("item", plaintext);
            var result = new byte[expected.Length];
            var written = cache.Decrypt("item", result);

            Assert.True(written > 0);
            Assert.Equal(expected, result[..written]);
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task Decrypt_Bytes_WithTooSmallResultBuffer_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();
        cache.Add("item", "top secret"u8.ToArray());

        var tooSmall = new byte[1];
        Assert.Throws<ArgumentException>(() => cache.Decrypt("item", tooSmall));
    }

    [Fact]
    public async Task Decrypt_Chars_WithTooSmallResultBuffer_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();
        cache.Add("item", "top secret chars".ToCharArray());

        var tooSmall = new char[1];
        Assert.Throws<ArgumentException>(() => cache.Decrypt("item", tooSmall));
    }

    [Fact]
    public async Task Add_Bytes_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();

        Assert.Throws<ArgumentNullException>(() => cache.Add(null!, "value"u8.ToArray()));
    }

    [Fact]
    public async Task Add_Chars_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();

        Assert.Throws<ArgumentNullException>(() => cache.Add(null!, "value".ToCharArray()));
    }

    [Fact]
    public async Task AddOrUpdate_Bytes_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();

        Assert.Throws<ArgumentNullException>(() => cache.AddOrUpdate(null!, "value"u8.ToArray()));
    }

    [Fact]
    public async Task AddOrUpdate_Chars_WithNullName_RecordsExceptionAndThrows()
    {
        var cache = await CreateCacheAsync();

        Assert.Throws<ArgumentNullException>(() => cache.AddOrUpdate(null!, "value".ToCharArray()));
    }

    [Fact]
    public async Task Decrypt_Bytes_WithMissingName_AndSensitiveLoggingEnabled_StillReturnsZero()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            var cache = await CreateCacheAsync();

            var written = cache.Decrypt("missing", new byte[16]);

            Assert.Equal(0, written);
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task ConcurrentAddAndDecrypt_AcrossManyNames_AllRoundTrip()
    {
        var cache = await CreateCacheAsync();
        const int itemCount = 200;

        Parallel.For(0, itemCount, i =>
        {
            cache.Add($"item-{i}", Encoding.UTF8.GetBytes($"value-{i}"));
        });

        Parallel.For(0, itemCount, i =>
        {
            cache.TryGetMaxDecryptedLength($"item-{i}", out var maxLength);
            var result = new byte[maxLength];
            var written = cache.Decrypt($"item-{i}", result);
            Assert.True(written > 0);
            Assert.Equal($"value-{i}", Encoding.UTF8.GetString(result, 0, written));
        });
    }

    [Fact]
    public async Task ConcurrentAdd_WithSameName_ExactlyOneSucceeds()
    {
        var cache = await CreateCacheAsync();
        const int attemptCount = 50;
        var succeeded = 0;

        Parallel.For(0, attemptCount, i =>
        {
            try
            {
                cache.Add("shared-name", Encoding.UTF8.GetBytes($"value-{i}"));
                Interlocked.Increment(ref succeeded);
            }
            catch (ArgumentException)
            {
                // expected for every attempt but the winner
            }
        });

        Assert.Equal(1, succeeded);
    }

    [Fact]
    public async Task Add_WithNullLogger_StillWorks()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        var cache = new ProtectedCache(TestRing.For(dataProtectionKey), logger: null);

        var exception = Record.Exception(() => cache.Add("item", "value"u8.ToArray()));

        Assert.Null(exception);
    }

    [Fact]
    public async Task Add_WithLoggerAndSensitiveLoggingEnabled_LogsSensitiveOperation()
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;

            var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
            var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
            var logger = new FakeLogger<ProtectedCache>();
            var cache = new ProtectedCache(TestRing.For(dataProtectionKey), logger);

            cache.Add("item", "value"u8.ToArray());

            var entry = Assert.Single(logger.Entries);
            Assert.Equal(LogLevel.Debug, entry.Level);
            Assert.Contains("item", entry.Message);
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task Add_WithLoggerWhenDuplicateNameThrows_LogsOperationFailed()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var dataProtectionKey = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        var logger = new FakeLogger<ProtectedCache>();
        var cache = new ProtectedCache(TestRing.For(dataProtectionKey), logger);
        cache.Add("item", "first"u8.ToArray());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second"u8.ToArray()));

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.IsType<ArgumentException>(entry.Exception);
    }

    private static async Task<(ProtectedCache Cache, FakeLogger<ProtectedCache> Logger)> CreateLoggingCacheAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        var logger = new FakeLogger<ProtectedCache>();
        return (new ProtectedCache(TestRing.For(key), logger), logger);
    }

    private static async Task WithCacheSensitiveLoggingAsync(Func<Task> action)
    {
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
        try
        {
            await action();
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    private static void AssertSingleDebugEntryFor(FakeLogger<ProtectedCache> logger, string name)
    {
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Contains(name, entry.Message);
    }

    [Fact]
    public Task AddChars_WithLoggerAndSensitiveLoggingEnabled_LogsSensitiveOperation()
        => WithCacheSensitiveLoggingAsync(async () =>
        {
            var (cache, logger) = await CreateLoggingCacheAsync();

            cache.Add("item", "value".ToCharArray());

            AssertSingleDebugEntryFor(logger, "item");
        });

    [Fact]
    public Task AddOrUpdateBytes_WithLoggerAndSensitiveLoggingEnabled_LogsSensitiveOperation()
        => WithCacheSensitiveLoggingAsync(async () =>
        {
            var (cache, logger) = await CreateLoggingCacheAsync();

            cache.AddOrUpdate("item", "value"u8.ToArray());

            AssertSingleDebugEntryFor(logger, "item");
        });

    [Fact]
    public Task AddOrUpdateChars_WithLoggerAndSensitiveLoggingEnabled_LogsSensitiveOperation()
        => WithCacheSensitiveLoggingAsync(async () =>
        {
            var (cache, logger) = await CreateLoggingCacheAsync();

            cache.AddOrUpdate("item", "value".ToCharArray());

            AssertSingleDebugEntryFor(logger, "item");
        });

    [Fact]
    public async Task AddChars_WithLoggerWhenDuplicateNameThrows_LogsOperationFailed()
    {
        var (cache, logger) = await CreateLoggingCacheAsync();
        cache.Add("item", "first".ToCharArray());

        Assert.Throws<ArgumentException>(() => cache.Add("item", "second".ToCharArray()));

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.IsType<ArgumentException>(entry.Exception);
    }

    [Fact]
    public async Task AddOrUpdateBytes_WithLoggerWhenEncryptionFails_LogsOperationFailed()
    {
        var (cache, logger) = await CreateLoggingCacheAsync();

        // The cache rejects empty values (0 from Decrypt means "not present").
        Assert.Throws<ArgumentException>(() => cache.AddOrUpdate("item", Span<byte>.Empty));

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.IsType<ArgumentException>(entry.Exception);
    }

    [Fact]
    public async Task AddOrUpdateChars_WithLoggerWhenEncryptionFails_LogsOperationFailed()
    {
        var (cache, logger) = await CreateLoggingCacheAsync();

        Assert.Throws<ArgumentException>(() => cache.AddOrUpdate("item", Span<char>.Empty));

        var entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.IsType<ArgumentException>(entry.Exception);
    }

    [Fact]
    public async Task Add_IncrementsCacheOperationsCounter_OnSuccessAndFailure()
    {
        var measurements = new List<(long Value, string? Operation, string? Result)>();
        using var meterListener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == HkdfGuardTelemetry.Cache.SourceName && instrument.Name == MetricNames.Cache.Operations)
                    listener.EnableMeasurementEvents(instrument);
            },
        };
        meterListener.SetMeasurementEventCallback<long>((_, measurement, tags, _) =>
        {
            string? operation = null;
            string? result = null;
            foreach (var tag in tags)
            {
                if (tag.Key == AttributeNames.OperationName)
                    operation = tag.Value?.ToString();
                else if (tag.Key == AttributeNames.Result)
                    result = tag.Value?.ToString();
            }

            measurements.Add((measurement, operation, result));
        });
        meterListener.Start();

        var cache = await CreateCacheAsync();
        cache.Add("item", "value"u8.ToArray());
        Assert.Throws<ArgumentException>(() => cache.Add("item", "value"u8.ToArray()));

        Assert.Contains(measurements, m => m is (1, ActivityNames.Cache.Add, "success"));
        Assert.Contains(measurements, m => m is (1, ActivityNames.Cache.Add, "error"));
    }

    [Fact]
    public async Task Add_WithAnEmptyValue_ThrowsForBothOverloadsAndStoresNothing()
    {
        var (cache, _) = await CreateLoggingCacheAsync();

        Assert.Throws<ArgumentException>(() => cache.Add("item", Span<byte>.Empty));
        Assert.Throws<ArgumentException>(() => cache.Add("item", Span<char>.Empty));
        Assert.False(cache.TryGetMaxDecryptedLength("item", out _));
    }

    [Fact]
    public async Task AddOrUpdate_WithALargeValue_RoundTripsThroughDecryptChars()
    {
        var (cache, _) = await CreateLoggingCacheAsync();
        var value = new string('x', 1024 * 1024);
        cache.AddOrUpdate("big", value.ToCharArray());

        Assert.True(cache.TryGetMaxDecryptedLength("big", out var maxLength));
        var result = new char[maxLength];
        var written = cache.Decrypt("big", result.AsSpan());

        Assert.Equal(value, new string(result, 0, written));
    }
}
