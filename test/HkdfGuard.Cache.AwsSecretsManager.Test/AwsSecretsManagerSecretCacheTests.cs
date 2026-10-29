using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Amazon;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.AwsSecretsManager.Test.TestHelpers;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.AwsSecretsManager.Test;

/// <summary>The cache's real Secrets Manager client, with its capture handler, against a fake endpoint.</summary>
public class AwsSecretsManagerSecretCacheTests
{
    private static async Task<(AwsSecretsManagerSecretCache Cache, FakeSecretsManager Aws)> CreateAsync(
        AWSCredentials? credentials = null, ILogger<AwsSecretsManagerSecretCache>? logger = null)
    {
        var aws = new FakeSecretsManager();
        return (new AwsSecretsManagerSecretCache(await TestRing.CreateAsync(), aws.Config(), credentials ?? FakeSecretsManager.Credentials, logger), aws);
    }

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    // What every response the client's unmarshaller produced held, read as it was produced.
    private static ConcurrentQueue<(string? Arn, string? SecretString, long? SecretBinaryLength)> Unmarshalled(AwsSecretsManagerSecretCache cache)
    {
        var responses = new ConcurrentQueue<(string?, string?, long?)>();
        cache.Client.AfterResponseEvent += (_, e) =>
        {
            var response = (GetSecretValueResponse)((WebServiceResponseEventArgs)e).Response;
            responses.Enqueue((response.ARN, response.SecretString, response.SecretBinary?.Length));
        };
        return responses;
    }

    [Fact]
    public async Task Decrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetString("prod/Db-Password", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "prod/Db-Password"));
        var bytes = new byte[64];
        Assert.Equal("s3cret", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("prod/Db-Password", bytes)));

        Assert.Equal(["prod/Db-Password"], aws.Gets);
        Assert.Empty(aws.UnexpectedOperations);
    }

    [Fact]
    public async Task TheUnmarshalledResponse_HoldsTheValueBlanked()
    {
        var (cache, aws) = await CreateAsync();
        var responses = Unmarshalled(cache);
        aws.SetString("text", "s3cret");
        aws.SetBinary("binary", [1, 2, 3]);

        Assert.Equal("s3cret", DecryptString(cache, "text"));
        Assert.Equal(3, cache.Decrypt("binary", new byte[16]));

        Assert.Equal(2, responses.Count);
        Assert.All(responses, r =>
        {
            Assert.True(string.IsNullOrEmpty(r.SecretString));
            Assert.True(r.SecretBinaryLength is null or 0);
            Assert.StartsWith("arn:aws:secretsmanager:", r.Arn, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task AValueWithJsonEscapes_IsUnescapedExactly()
    {
        var (cache, aws) = await CreateAsync();
        const string secret = "p\"a\\ss/wörd\n\u0001秘密";
        aws.SetString("escaped", secret);

        Assert.Equal(secret, DecryptString(cache, "escaped"));
    }

    [Fact]
    public async Task ABinarySecret_IsCachedAsItsBytes()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetBinary("binary", [0, 1, 254, 255]);

        var result = new byte[16];
        var written = cache.Decrypt("binary", result);

        Assert.Equal(new byte[] { 0, 1, 254, 255 }, result[..written]);
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
    public async Task AKeyValueSecret_IsCachedWholeAndByKey_FromOneCall_AndTheSdkNeverSeesIt()
    {
        var (cache, aws) = await CreateAsync();
        var responses = Unmarshalled(cache);
        aws.SetString("prod/App", KeyValueSecret);

        Assert.Equal("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==", DecryptLong(cache, "prod/App#api-credential-21"));
        Assert.Equal("This is my first credential", DecryptLong(cache, "prod/App#test-credential-1"));
        Assert.Equal("This is my third credential", DecryptLong(cache, "prod/App#service-credential-3"));
        Assert.Equal("fakedomain/thiscredential", DecryptLong(cache, "prod/App#domain-credential-17"));
        Assert.Equal("5432", DecryptLong(cache, "prod/App#port"));
        Assert.Equal(KeyValueSecret, DecryptLong(cache, "prod/App"));
        Assert.Equal(0, cache.Decrypt("prod/app#port", new byte[16]));

        Assert.Equal(["prod/App", "prod/app"], aws.Gets);
        Assert.True(string.IsNullOrEmpty(responses.First().SecretString));
    }

    [Fact]
    public async Task ABinarySecretHoldingJson_IsNotSplit()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetBinary("binary", Encoding.UTF8.GetBytes("""{"k":"v"}"""));

        Assert.Equal("""{"k":"v"}""", DecryptLong(cache, "binary"));
        Assert.Equal(0, cache.Decrypt("binary#k", new byte[16]));
    }

    [Fact]
    public async Task DecryptAsync_FetchesWithoutBlocking_AndTheSdkNeverSeesTheValue()
    {
        var (cache, aws) = await CreateAsync();
        var responses = Unmarshalled(cache);
        aws.SetString("prod/App", KeyValueSecret);

        var chars = new char[512];
        Assert.Equal("This is my first credential", new string(chars, 0, await cache.DecryptAsync("prod/App#test-credential-1", chars.AsMemory())));
        Assert.Equal(KeyValueSecret, new string(chars, 0, await cache.DecryptAsync("prod/App", chars.AsMemory())));
        Assert.True(await cache.GetMaxDecryptedLengthAsync("prod/App#port") >= 4);
        Assert.Equal(0, await cache.DecryptAsync("missing", new byte[16].AsMemory()));

        Assert.Equal(["prod/App", "missing"], aws.Gets);
        Assert.True(string.IsNullOrEmpty(responses.First().SecretString));
    }

    [Fact]
    public async Task DecryptAsync_PropagatesAnAwsFailure_AndACancellation()
    {
        var (cache, aws) = await CreateAsync();
        aws.FailWith = ("InvalidRequestException", HttpStatusCode.BadRequest);
        await Assert.ThrowsAsync<InvalidRequestException>(() => cache.DecryptAsync("item", new byte[16].AsMemory()).AsTask());

        aws.FailWith = null;
        aws.SetString("item", "value");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cache.DecryptAsync("item", new byte[16].AsMemory(), new CancellationToken(canceled: true)).AsTask());
        Assert.Equal(5, await cache.DecryptAsync("item", new byte[16].AsMemory()));
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_OnMiss_FetchesTheSecret()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetString("api-key", "value");

        Assert.True(cache.TryGetMaxDecryptedLength("api-key", out var max));
        Assert.True(max >= 5);
        Assert.Equal("value", DecryptString(cache, "api-key"));
        Assert.Single(aws.Gets);
    }

    [Fact]
    public async Task NamesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetString("prod/Db", "upper");
        aws.SetString("prod/db", "lower");

        Assert.Equal("upper", DecryptString(cache, "prod/Db"));
        Assert.Equal("lower", DecryptString(cache, "prod/db"));
        Assert.Equal(0, cache.Decrypt("PROD/DB", new byte[16]));
        Assert.Equal("upper", DecryptString(cache, "prod/Db"));

        Assert.Equal(["prod/Db", "prod/db", "PROD/DB"], aws.Gets);
    }

    [Fact]
    public async Task AMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists()
    {
        var (cache, aws) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("later", new byte[16]));
        Assert.False(cache.TryGetMaxDecryptedLength("later", out var max));
        Assert.Equal(0, max);

        aws.SetString("later", "now here");
        Assert.Equal("now here", DecryptString(cache, "later"));
        Assert.Equal(3, aws.Gets.Count);
    }

    [Fact]
    public async Task AnEmptySecret_IsReportedMissing()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetEmpty("none");
        aws.SetString("empty-string", "");
        aws.SetBinary("empty-binary", []);

        Assert.Equal(0, cache.Decrypt("none", new byte[16]));
        Assert.Equal(0, cache.Decrypt("empty-string", new byte[16]));
        Assert.Equal(0, cache.Decrypt("empty-binary", new byte[16]));
    }

    [Theory]
    [InlineData("""{"SecretString":"a","SecretBinary":"Yg=="}""")]
    [InlineData("""{"SecretBinary":"not base64!"}""")]
    [InlineData("not json")]
    public async Task AResponseThatCantBeTrusted_IsRefused(string body)
    {
        var (cache, aws) = await CreateAsync();
        aws.RawBody = body;

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf")]
    [InlineData("has space")]
    [InlineData("café")]
    [InlineData("bang!")]
    public async Task ANameSecretsManagerCantHold_IsMissing_WithoutCallingAws(string name)
    {
        var (cache, aws) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.Equal(0, cache.Decrypt(name, new char[16].AsSpan()));
        Assert.False(cache.TryGetMaxDecryptedLength(name, out var max));
        Assert.Equal(0, max);
        Assert.Empty(aws.Gets);
    }

    [Fact]
    public void IsValidSecretName_AcceptsTheSecretsManagerCharacterSet_UpTo512()
    {
        Assert.True(AwsSecretsManagerSecretCache.IsValidSecretName("a"));
        Assert.True(AwsSecretsManagerSecretCache.IsValidSecretName("prod/app_1+x=y.z@w-v"));
        Assert.True(AwsSecretsManagerSecretCache.IsValidSecretName(new string('x', AwsSecretsManagerSecretCache.MaxSecretNameLength)));
        Assert.False(AwsSecretsManagerSecretCache.IsValidSecretName(new string('x', AwsSecretsManagerSecretCache.MaxSecretNameLength + 1)));
        Assert.False(AwsSecretsManagerSecretCache.IsValidSecretName(null));
    }

    [Fact]
    public async Task AnAwsFailure_Propagates_AndIsRetriedOnTheNextLookup()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetString("item", "value");
        aws.FailWith = ("InvalidRequestException", HttpStatusCode.BadRequest);

        Assert.Throws<InvalidRequestException>(() => cache.Decrypt("item", new byte[16]));

        aws.FailWith = null;
        Assert.Equal("value", DecryptString(cache, "item"));
        Assert.Equal(2, aws.Gets.Count);
    }

    [Fact]
    public async Task ACredentialFailure_Propagates()
    {
        var (cache, _) = await CreateAsync(new ThrowingCredentials());

        Assert.Throws<AmazonClientException>(() => cache.Decrypt("item", new char[16].AsSpan()));
    }

    [Fact]
    public async Task ConcurrentMissesOnOneName_ShareOneFetch()
    {
        var (cache, aws) = await CreateAsync();
        aws.SetString("shared", "value");
        using var release = new ManualResetEventSlim();
        aws.OnGet = () => release.Wait(TimeSpan.FromSeconds(10));

        var lookups = Enumerable.Range(0, 8).Select(_ => Task.Run(() => DecryptString(cache, "shared"))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.All(await Task.WhenAll(lookups), value => Assert.Equal("value", value));
        Assert.Single(aws.Gets);
    }

    [Fact]
    public async Task ALargeSecret_RoundTrips()
    {
        var (cache, aws) = await CreateAsync();
        var large = string.Concat(Enumerable.Repeat("é-秘密-", 1500));
        Assert.True(Encoding.UTF8.GetByteCount(large) > ArrayUtility.MaxStackBytes);
        aws.SetString("large", large);

        Assert.True(cache.TryGetMaxDecryptedLength("large", out var max));
        var result = new char[max];
        Assert.Equal(large, new string(result, 0, cache.Decrypt("large", result.AsSpan())));
    }

    [Fact]
    public async Task ACachedSecret_StillDecryptsAfterTheRingRotates()
    {
        var aws = new FakeSecretsManager();
        await using var ring = await TestRing.CreateAsync();
        using var cache = new AwsSecretsManagerSecretCache(ring, aws.Config(), FakeSecretsManager.Credentials);
        aws.SetString("before", "v1 value");
        aws.SetString("after", "v2 value");

        Assert.Equal("v1 value", DecryptString(cache, "before"));
        ring.Add(2, await TestRing.NewKeyAsync());

        Assert.Equal("v2 value", DecryptString(cache, "after"));
        Assert.Equal("v1 value", DecryptString(cache, "before"));
    }

    [Fact]
    public async Task InACollection_OnlyNamesTheEarlierSourcesMiss_ReachAws()
    {
        var (awsCache, aws) = await CreateAsync();
        aws.SetString("from-aws", "aws value");
        var local = new ProtectedCache(await TestRing.CreateAsync());
        local.Add("ConnectionStrings:Admin", "local value".ToCharArray());
        var collection = new ProtectedCacheCollection().Add(local).Add(awsCache);

        Assert.Equal("local value", DecryptString(collection, "ConnectionStrings:Admin"));
        Assert.Equal("aws value", DecryptString(collection, "from-aws"));
        Assert.Equal(["from-aws"], aws.Gets);
    }

    [Fact]
    public async Task WithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError()
    {
        var logger = new FakeLogger<AwsSecretsManagerSecretCache>();
        var (cache, aws) = await CreateAsync(logger: logger);
        aws.SetString("prod/Item", "never-logged");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("never-logged", DecryptString(cache, "prod/Item"));
            aws.FailWith = ("InternalServiceError", HttpStatusCode.InternalServerError);
            Assert.Throws<InternalServiceErrorException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        // The secret's own name, not its escaped entry name.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("prod/Item", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Exception is InternalServiceErrorException);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("never-logged", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheDefaults_MakeNoCallUntilASecretIsRequested()
    {
        // Region and credentials resolve on the first call, so none is needed for this.
        Environment.SetEnvironmentVariable("AWS_REGION", Environment.GetEnvironmentVariable("AWS_REGION") ?? RegionEndpoint.USEast1.SystemName);
        using var cache = new AwsSecretsManagerSecretCache(await TestRing.CreateAsync());

        Assert.Equal(0, cache.Decrypt("not:a:secret", new byte[16]));
    }

    [Fact]
    public void TheConstructor_RejectsANullRing()
        => Assert.Throws<ArgumentNullException>(() => new AwsSecretsManagerSecretCache(null!));

    private sealed class ThrowingCredentials : AWSCredentials
    {
        public override ImmutableCredentials GetCredentials() => throw new AmazonClientException("Unable to get IAM security credentials.");

        public override Task<ImmutableCredentials> GetCredentialsAsync() => throw new AmazonClientException("Unable to get IAM security credentials.");
    }
}
