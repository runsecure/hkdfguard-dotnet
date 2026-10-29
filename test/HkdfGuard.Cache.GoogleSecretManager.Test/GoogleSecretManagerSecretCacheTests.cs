using System.Security.Cryptography;
using System.Text;
using Google.Cloud.SecretManager.V1;
using Grpc.Core;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.GoogleSecretManager.Test.TestHelpers;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.GoogleSecretManager.Test;

public class GoogleSecretManagerSecretCacheTests
{
    private static async Task<(GoogleSecretManagerSecretCache Cache, FakeSecretManager Google)> CreateAsync()
    {
        var google = new FakeSecretManager();
        return (new GoogleSecretManagerSecretCache(google, FakeSecretManager.ProjectId, await TestRing.CreateAsync()), google);
    }

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task Decrypt_OnMiss_FetchesTheOneSecretsLatestVersion_ThenServesItFromTheCache()
    {
        var (cache, google) = await CreateAsync();
        google.Set("Db-Password", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "Db-Password"));
        var bytes = new byte[64];
        Assert.Equal("s3cret", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("Db-Password", bytes)));

        Assert.Equal(["projects/hkdfguard-test/secrets/Db-Password/versions/latest"], google.Accesses);
    }

    [Fact]
    public async Task TheDeserializedPayload_AndGrpcsReceiveBuffer_AreZeroedOnceEncrypted()
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");

        Assert.Equal("value", DecryptString(cache, "item"));

        Assert.All(Assert.Single(google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(google.ReceiveBuffers), b => Assert.Equal(0, b));
        Assert.Empty(google.UnexpectedCalls);
    }

    // A key/value secret as AWS Secrets Manager's console stores one.
    private const string KeyValueSecret = """
        {
          "test-credential-1": "This is my first credential",
          "service-credential-3": "This is my third credential",
          "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
          "domain-credential-17": "fakedomain/thiscredential",
          "port": 5432
        }
        """;

    private static string DecryptLong(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[512];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task AJsonPayload_IsCachedWholeAndByKey_FromOneCall_AndIsZeroed()
    {
        var (cache, google) = await CreateAsync();
        google.Set("App-Credentials", KeyValueSecret);

        Assert.Equal("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==", DecryptLong(cache, "App-Credentials#api-credential-21"));
        Assert.Equal("This is my third credential", DecryptLong(cache, "App-Credentials#service-credential-3"));
        Assert.Equal("5432", DecryptLong(cache, "App-Credentials#port"));
        Assert.Equal(KeyValueSecret, DecryptLong(cache, "App-Credentials"));

        Assert.Equal(["App-Credentials"], google.Gets);
        Assert.All(Assert.Single(google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(google.ReceiveBuffers), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task DecryptAsync_FetchesAsynchronously_AndZeroesThePayloadAndReceiveBuffer()
    {
        var (cache, google) = await CreateAsync();
        google.Set("App-Credentials", KeyValueSecret);

        var chars = new char[512];
        Assert.Equal("This is my third credential", new string(chars, 0, await cache.DecryptAsync("App-Credentials#service-credential-3", chars.AsMemory())));
        Assert.Equal(KeyValueSecret, new string(chars, 0, await cache.DecryptAsync("App-Credentials", chars.AsMemory())));
        Assert.Equal(0, await cache.DecryptAsync("Missing", new byte[16].AsMemory()));

        Assert.Equal(2, google.AsyncCalls);
        Assert.All(Assert.Single(google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(google.ReceiveBuffers), b => Assert.Equal(0, b));
        Assert.Empty(google.UnexpectedCalls);
    }

    [Fact]
    public async Task DecryptAsync_PropagatesAGoogleFailure()
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");
        google.Failure = new RpcException(new Status(StatusCode.PermissionDenied, "Denied in a test."));

        var e = await Assert.ThrowsAsync<RpcException>(() => cache.DecryptAsync("item", new byte[16].AsMemory()).AsTask());
        Assert.Equal(StatusCode.PermissionDenied, e.StatusCode);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_OnMiss_FetchesTheSecret()
    {
        var (cache, google) = await CreateAsync();
        google.Set("api-key", "value");

        Assert.True(cache.TryGetMaxDecryptedLength("api-key", out var max));
        Assert.True(max >= 5);
        Assert.Equal("value", DecryptString(cache, "api-key"));
        Assert.Single(google.Accesses);
    }

    [Fact]
    public async Task NamesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries()
    {
        var (cache, google) = await CreateAsync();
        google.Set("Db", "upper");
        google.Set("db", "lower");

        Assert.Equal("upper", DecryptString(cache, "Db"));
        Assert.Equal("lower", DecryptString(cache, "db"));
        Assert.Equal(0, cache.Decrypt("DB", new byte[16]));
        Assert.Equal("upper", DecryptString(cache, "Db"));

        Assert.Equal(["Db", "db", "DB"], google.Gets);
    }

    [Fact]
    public async Task AMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists()
    {
        var (cache, google) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("later", new byte[16]));
        Assert.False(cache.TryGetMaxDecryptedLength("later", out var max));
        Assert.Equal(0, max);

        google.Set("later", "now here");
        Assert.Equal("now here", DecryptString(cache, "later"));
        Assert.Equal(3, google.Accesses.Count);
    }

    [Fact]
    public async Task AnEmptyOrAbsentPayload_IsReportedMissing()
    {
        var (cache, google) = await CreateAsync();
        google.Set("empty", []);

        Assert.Equal(0, cache.Decrypt("empty", new byte[16]));

        google.Tamper = response => response.Payload = null;
        google.Set("no-payload", "value");
        Assert.Equal(0, cache.Decrypt("no-payload", new byte[16]));
    }

    [Fact]
    public async Task ABinarySecret_IsCachedAsItsBytes()
    {
        var (cache, google) = await CreateAsync();
        google.Set("binary", [0, 1, 254, 255]);

        var result = new byte[16];
        var written = cache.Decrypt("binary", result);

        Assert.Equal(new byte[] { 0, 1, 254, 255 }, result[..written]);
    }

    [Fact]
    public async Task APayloadWithoutAChecksum_IsAccepted()
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");
        google.Tamper = response => response.Payload.ClearDataCrc32C();

        Assert.Equal("value", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task APayloadThatDoesNotMatchItsChecksum_IsRefused_AndZeroed()
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");
        google.Tamper = response => response.Payload.DataCrc32C ^= 1;

        Assert.Throws<CryptographicException>(() => cache.Decrypt("item", new byte[16]));
        Assert.All(Assert.Single(google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(google.ReceiveBuffers), b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData("projects/123456789012/secrets/other/versions/1")]
    [InlineData("not a resource name")]
    public async Task AResponseForAnotherSecret_IsRefused(string reportedName)
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");
        google.Tamper = response => response.Name = reportedName;

        Assert.Throws<CryptographicException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("prod/db")]
    [InlineData("db.password")]
    [InlineData("has space")]
    [InlineData("café")]
    [InlineData("bang!")]
    public async Task ANameSecretManagerCantHold_IsMissing_WithoutCallingGoogle(string name)
    {
        var (cache, google) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.Equal(0, cache.Decrypt(name, new char[16].AsSpan()));
        Assert.False(cache.TryGetMaxDecryptedLength(name, out var max));
        Assert.Equal(0, max);
        Assert.Empty(google.Accesses);
    }

    [Fact]
    public void IsValidSecretName_AcceptsLettersDigitsHyphensAndUnderscores_UpTo255()
    {
        Assert.True(GoogleSecretManagerSecretCache.IsValidSecretName("a"));
        Assert.True(GoogleSecretManagerSecretCache.IsValidSecretName("Db_Password-2"));
        Assert.True(GoogleSecretManagerSecretCache.IsValidSecretName(new string('x', GoogleSecretManagerSecretCache.MaxSecretNameLength)));
        Assert.False(GoogleSecretManagerSecretCache.IsValidSecretName(new string('x', GoogleSecretManagerSecretCache.MaxSecretNameLength + 1)));
        Assert.False(GoogleSecretManagerSecretCache.IsValidSecretName(null));
    }

    [Theory]
    [InlineData(StatusCode.PermissionDenied)]
    [InlineData(StatusCode.FailedPrecondition)] // the latest version is disabled or destroyed
    public async Task AGoogleFailure_Propagates_AndIsRetriedOnTheNextLookup(StatusCode status)
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");
        google.Failure = new RpcException(new Status(status, "refused"));

        var thrown = Assert.Throws<RpcException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Equal(status, thrown.StatusCode);

        google.Failure = null;
        Assert.Equal("value", DecryptString(cache, "item"));
        Assert.Equal(2, google.Accesses.Count);
    }

    [Fact]
    public async Task ConcurrentMissesOnOneName_ShareOneFetch()
    {
        var (cache, google) = await CreateAsync();
        google.Set("shared", "value");
        using var release = new ManualResetEventSlim();
        google.OnGet = () => release.Wait(TimeSpan.FromSeconds(10));

        var lookups = Enumerable.Range(0, 8).Select(_ => Task.Run(() => DecryptString(cache, "shared"))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.All(await Task.WhenAll(lookups), value => Assert.Equal("value", value));
        Assert.Single(google.Accesses);
    }

    [Fact]
    public async Task ALargeSecret_RoundTrips()
    {
        var (cache, google) = await CreateAsync();
        var large = string.Concat(Enumerable.Repeat("é-秘密-", 1500));
        Assert.True(Encoding.UTF8.GetByteCount(large) > ArrayUtility.MaxStackBytes);
        google.Set("large", large);

        Assert.True(cache.TryGetMaxDecryptedLength("large", out var max));
        var result = new char[max];
        Assert.Equal(large, new string(result, 0, cache.Decrypt("large", result.AsSpan())));
    }

    [Fact]
    public async Task ACachedSecret_StillDecryptsAfterTheRingRotates()
    {
        var google = new FakeSecretManager();
        await using var ring = await TestRing.CreateAsync();
        var cache = new GoogleSecretManagerSecretCache(google, FakeSecretManager.ProjectId, ring);
        google.Set("before", "v1 value");
        google.Set("after", "v2 value");

        Assert.Equal("v1 value", DecryptString(cache, "before"));
        ring.Add(2, await TestRing.NewKeyAsync());

        Assert.Equal("v2 value", DecryptString(cache, "after"));
        Assert.Equal("v1 value", DecryptString(cache, "before"));
    }

    [Fact]
    public async Task InACollection_OnlyNamesTheEarlierSourcesMiss_ReachGoogle()
    {
        var (googleCache, google) = await CreateAsync();
        google.Set("from-google", "google value");
        var local = new ProtectedCache(await TestRing.CreateAsync());
        local.Add("ConnectionStrings:Admin", "local value".ToCharArray());
        var collection = new ProtectedCacheCollection().Add(local).Add(googleCache);

        Assert.Equal("local value", DecryptString(collection, "ConnectionStrings:Admin"));
        Assert.Equal("google value", DecryptString(collection, "from-google"));
        Assert.Equal(["from-google"], google.Gets);
    }

    [Fact]
    public async Task WithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError()
    {
        var google = new FakeSecretManager();
        google.Set("Item", "never-logged");
        var logger = new FakeLogger<GoogleSecretManagerSecretCache>();
        var cache = new GoogleSecretManagerSecretCache(google, FakeSecretManager.ProjectId, await TestRing.CreateAsync(), logger);

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("never-logged", DecryptString(cache, "Item"));
            google.Failure = new RpcException(new Status(StatusCode.Internal, "boom"));
            Assert.Throws<RpcException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        // The secret's own name, not its escaped entry name.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("Item", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Exception is RpcException);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("never-logged", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutALogger_FetchesAndFailuresStillWork_WithOrWithoutSensitiveLogging()
    {
        var (cache, google) = await CreateAsync();
        google.Set("item", "value");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("value", DecryptString(cache, "item"));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        google.Failure = new RpcException(new Status(StatusCode.Internal, "boom"));
        Assert.Throws<RpcException>(() => cache.Decrypt("other", new byte[16]));
    }

    [Fact]
    public async Task Create_MakesItsOwnChannel_WithoutCallingGoogleUntilASecretIsRequested()
    {
        using var cache = GoogleSecretManagerSecretCache.Create(FakeSecretManager.ProjectId,
            Google.Apis.Auth.OAuth2.GoogleCredential.FromAccessToken("fake-token"), await TestRing.CreateAsync());

        // An invalid name never reaches the channel, so this needs no network.
        Assert.Equal(0, cache.Decrypt("not:a:secret", new byte[16]));
    }

    [Fact]
    public async Task Create_RejectsANullCredential_AndAnInvalidProject()
    {
        var ring = await TestRing.CreateAsync();

        Assert.Throws<ArgumentNullException>(() => GoogleSecretManagerSecretCache.Create("p", null!, ring));
        Assert.Throws<ArgumentException>(() => GoogleSecretManagerSecretCache.Create("p/x",
            Google.Apis.Auth.OAuth2.GoogleCredential.FromAccessToken("fake-token"), ring));
    }

    [Fact]
    public async Task Dispose_LeavesACallersOwnInvokerUsable()
    {
        var google = new FakeSecretManager();
        google.Set("item", "value");
        new GoogleSecretManagerSecretCache(google, FakeSecretManager.ProjectId, await TestRing.CreateAsync()).Dispose();

        var cache = new GoogleSecretManagerSecretCache(google, FakeSecretManager.ProjectId, await TestRing.CreateAsync());
        Assert.Equal("value", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task TheConstructor_RejectsNullsAndProjectIdsThatCouldChangeTheResourcePath()
    {
        var ring = await TestRing.CreateAsync();
        var google = new FakeSecretManager();

        Assert.Throws<ArgumentNullException>(() => new GoogleSecretManagerSecretCache(null!, "p", ring));
        Assert.Throws<ArgumentNullException>(() => new GoogleSecretManagerSecretCache(google, null!, ring));
        Assert.Throws<ArgumentNullException>(() => new GoogleSecretManagerSecretCache(google, "p", null!));
        Assert.Throws<ArgumentException>(() => new GoogleSecretManagerSecretCache(google, "", ring));
        Assert.Throws<ArgumentException>(() => new GoogleSecretManagerSecretCache(google, "p/secrets/other", ring));
        Assert.Throws<ArgumentException>(() => new GoogleSecretManagerSecretCache(google, "my project", ring));

        // A project number, and a legacy domain-scoped ID, are both fine.
        _ = new GoogleSecretManagerSecretCache(google, "123456789012", ring);
        _ = new GoogleSecretManagerSecretCache(google, "example.com:my-project", ring);
    }

    [Fact]
    public void Crc32C_MatchesTheCastagnoliCheckValue()
        => Assert.Equal(0xE3069283L, GoogleSecretManagerSecretCache.Crc32C("123456789"u8));
}
