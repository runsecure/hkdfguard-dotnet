using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.Test;

/// <summary>RemoteSecretCache's fetch-on-miss, name matching and SecretValueSink, over a fake store.</summary>
public class RemoteSecretCacheTests
{
    private static async Task<IKeyRing> NewRingAsync()
        => TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60)));

    private static async Task<FakeRemoteSecretCache> CreateAsync(SecretNameMatching matching = SecretNameMatching.Exact, ILogger? logger = null)
        => new(await NewRingAsync(), matching, logger);

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task AMiss_FetchesOnce_ThenEveryOverloadIsServedFromTheCache()
    {
        var cache = await CreateAsync();
        cache.Set("item", "value");

        Assert.True(cache.TryGetMaxDecryptedLength("item", out var max));
        Assert.True(max >= 5);
        Assert.Equal("value", DecryptString(cache, "item"));
        var bytes = new byte[16];
        Assert.Equal("value", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("item", bytes)));

        Assert.Equal(["item"], cache.Fetches);
    }

    [Fact]
    public async Task IgnoreAsciiCase_SpellingsDifferingInCase_ShareOneEntryAndOneFetch()
    {
        var cache = await CreateAsync(SecretNameMatching.IgnoreAsciiCase);
        cache.Set("Db-Password", "value");

        Assert.Equal("value", DecryptString(cache, "db-password"));
        Assert.Equal("value", DecryptString(cache, "DB-PASSWORD"));
        Assert.Equal(["db-password"], cache.Fetches);
    }

    [Fact]
    public async Task Exact_SpellingsDifferingInCase_AreSeparateEntries_FetchedByTheirOwnSpelling()
    {
        var cache = await CreateAsync();
        cache.Set("prod/Db", "upper");
        cache.Set("prod/db", "lower");

        Assert.Equal("upper", DecryptString(cache, "prod/Db"));
        Assert.Equal("lower", DecryptString(cache, "prod/db"));
        Assert.Equal(0, cache.Decrypt("PROD/DB", new byte[16]));
        Assert.Equal("upper", DecryptString(cache, "prod/Db"));

        Assert.Equal(["prod/Db", "prod/db", "PROD/DB"], cache.Fetches);
    }

    [Fact]
    public async Task Exact_ANameHoldingTheCaseMarker_IsMissing_WithoutAFetch()
    {
        var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("prod/!db", new byte[16]));
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task IgnoreAsciiCase_ANameHoldingTheCaseMarker_IsFetchedLikeAnyOther()
    {
        var cache = await CreateAsync(SecretNameMatching.IgnoreAsciiCase);
        cache.Set("bang!", "value");

        Assert.Equal("value", DecryptString(cache, "bang!"));
    }

    [Theory]
    [InlineData("prod/Db")]
    [InlineData("ALLCAPS")]
    [InlineData("a/B_c+D=e.F@g-H")]
    [InlineData("nocaps")]
    public void EntryName_RoundTrips_AndHoldsNoUpperCase(string name)
    {
        var entry = RemoteSecretCache.EntryName(name);

        Assert.DoesNotContain(entry, char.IsAsciiLetterUpper);
        Assert.Equal(name, RemoteSecretCache.SecretName(entry));
    }

    [Fact]
    public async Task AnInvalidName_IsMissing_WithoutAFetch()
    {
        var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("Connection:Strings", new byte[16]));
        Assert.Equal(0, cache.Decrypt("Connection:Strings", new char[16].AsSpan()));
        Assert.False(cache.TryGetMaxDecryptedLength("Connection:Strings", out var max));
        Assert.Equal(0, max);
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task ANullName_Throws()
    {
        var cache = await CreateAsync();

        Assert.Throws<ArgumentNullException>(() => cache.Decrypt(null!, new byte[16]));
        Assert.Throws<ArgumentNullException>(() => cache.TryGetMaxDecryptedLength(null!, out _));
    }

    [Fact]
    public async Task AFetchThatSetsNothing_IsMissing_AndIsFetchedAgainNextTime()
    {
        var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("later", new byte[16]));
        cache.Set("later", "now here");
        Assert.Equal("now here", DecryptString(cache, "later"));
        Assert.Equal(2, cache.Fetches.Count);
    }

    [Fact]
    public async Task AnEmptyValue_IsMissing()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => sink.SetBytes([]);
        Assert.Equal(0, cache.Decrypt("empty", new byte[16]));

        cache.OnFetch = (_, sink) => sink.SetText("");
        Assert.Equal(0, cache.Decrypt("empty", new byte[16]));
    }

    [Fact]
    public async Task SetBytes_StoresTheBytes_AndZeroesThem()
    {
        var cache = await CreateAsync();
        var given = new byte[] { 1, 2, 3 };
        cache.OnFetch = (_, sink) => sink.SetBytes(given);

        var result = new byte[16];
        var written = cache.Decrypt("binary", result);

        Assert.Equal(new byte[] { 1, 2, 3 }, result[..written]);
        Assert.All(given, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task SetText_PastTheStackLimit_RoundTrips()
    {
        var cache = await CreateAsync();
        var large = string.Concat(Enumerable.Repeat("é-秘密-", 1500));
        Assert.True(Encoding.UTF8.GetByteCount(large) > ArrayUtility.MaxStackBytes);
        cache.Set("large", large);

        Assert.True(cache.TryGetMaxDecryptedLength("large", out var max));
        var result = new char[max];
        Assert.Equal(large, new string(result, 0, cache.Decrypt("large", result.AsSpan())));
    }

    [Fact]
    public async Task SettingASecondValue_Throws_AndNothingIsCached()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) =>
        {
            sink.SetText("first");
            sink.SetText("second");
        };

        Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new byte[16]));

        cache.OnFetch = null;
        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ASinkKeptPastItsFetch_RefusesEveryValue()
    {
        var cache = await CreateAsync();
        SecretValueSink? kept = null;
        cache.OnFetch = (_, sink) => kept = sink;
        Assert.Equal(0, cache.Decrypt("item", new byte[16]));

        var bytes = new byte[] { 9 };
        Assert.Throws<InvalidOperationException>(() => kept!.SetBytes(bytes));
        Assert.Equal(0, bytes[0]);
        Assert.Throws<InvalidOperationException>(() => kept!.SetText("late"));

        cache.OnFetch = (_, sink) =>
        {
            kept = sink;
            throw new TimeoutException("unreachable");
        };
        Assert.Throws<TimeoutException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Throws<InvalidOperationException>(() => kept!.SetText("late"));
    }

    [Fact]
    public async Task AFetchFailure_Propagates_AndIsRetriedOnTheNextLookup()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, _) => throw new TimeoutException("unreachable");

        Assert.Throws<TimeoutException>(() => cache.Decrypt("item", new byte[16]));

        cache.OnFetch = null;
        cache.Set("item", "value");
        Assert.Equal("value", DecryptString(cache, "item"));
        Assert.Equal(2, cache.Fetches.Count);
    }

    [Fact]
    public async Task ConcurrentMissesOnOneName_ShareOneFetch()
    {
        var cache = await CreateAsync();
        using var release = new ManualResetEventSlim();
        cache.OnFetch = (_, sink) =>
        {
            release.Wait(TimeSpan.FromSeconds(10));
            sink.SetText("value");
        };

        var lookups = Enumerable.Range(0, 8).Select(_ => Task.Run(() => DecryptString(cache, "shared"))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.All(await Task.WhenAll(lookups), value => Assert.Equal("value", value));
        Assert.Single(cache.Fetches);
    }

    [Fact]
    public async Task WithSensitiveLogging_AFetchLogsTheSecretsOwnName_AndAFailureLogsAnError()
    {
        var logger = new FakeLogger<RemoteSecretCache>();
        var cache = await CreateAsync(SecretNameMatching.Exact, logger);
        cache.Set("prod/Item", "never-logged");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("never-logged", DecryptString(cache, "prod/Item"));
            cache.OnFetch = (_, _) => throw new TimeoutException("boom");
            Assert.Throws<TimeoutException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        // The secret's own spelling, not its escaped entry name.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("prod/Item", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Exception is TimeoutException);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("never-logged", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutALogger_FetchesAndFailuresStillWork_WithSensitiveLogging()
    {
        var cache = await CreateAsync(SecretNameMatching.IgnoreAsciiCase);
        cache.Set("item", "value");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("value", DecryptString(cache, "item"));
            cache.OnFetch = (_, _) => throw new TimeoutException("boom");
            Assert.Throws<TimeoutException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public void TheConstructor_RejectsANullRing()
        => Assert.Throws<ArgumentNullException>(() => new FakeRemoteSecretCache(null!, SecretNameMatching.Exact));
}
