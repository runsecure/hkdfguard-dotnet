using System.Net;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.AzureKeyVault.Test;

/// <summary>A real SecretClient, with the cache's own pipeline policy, against a fake Key Vault endpoint.</summary>
public class AzureKeyVaultSecretCacheTests
{
    private static async Task<(AzureKeyVaultSecretCache Cache, FakeKeyVault Vault)> CreateAsync(
        TokenCredential? credential = null, ILogger<AzureKeyVaultSecretCache>? logger = null)
    {
        var vault = new FakeKeyVault();
        var cache = new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, credential ?? new FakeCredential(), await TestRing.CreateAsync(), vault.Options(), logger);
        return (cache, vault);
    }

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task Decrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("Db-Password", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "Db-Password"));
        var bytes = new byte[64];
        Assert.Equal("s3cret", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("Db-Password", bytes)));

        Assert.Equal(["Db-Password"], vault.Gets);
        Assert.Empty(vault.UnexpectedRequests);
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
    public async Task AJsonSecret_IsCachedWholeAndByKey_FromOneCall_AndSecretClientNeverSeesIt()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("App-Credentials", KeyValueSecret);

        Assert.Equal("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==", DecryptLong(cache, "App-Credentials#api-credential-21"));
        Assert.Equal("This is my first credential", DecryptLong(cache, "app-credentials#test-credential-1"));
        Assert.Equal("fakedomain/thiscredential", DecryptLong(cache, "APP-CREDENTIALS#domain-credential-17"));
        Assert.Equal("5432", DecryptLong(cache, "App-Credentials#port"));
        Assert.Equal(KeyValueSecret, DecryptLong(cache, "App-Credentials"));

        // Secret names ignore case; keys don't.
        Assert.Equal(0, cache.Decrypt("App-Credentials#PORT", new byte[16]));

        Assert.Equal(["App-Credentials", "App-Credentials"], vault.Gets);
        Assert.All(vault.BodiesSeenBySecretClient, body => Assert.DoesNotContain("credential", body, StringComparison.Ordinal));
    }

    [Fact]
    public async Task DecryptAsync_FetchesOnTheAsyncPipeline_AndSecretClientNeverSeesTheValue()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("App-Credentials", KeyValueSecret);

        var chars = new char[512];
        Assert.Equal("fakedomain/thiscredential", new string(chars, 0, await cache.DecryptAsync("App-Credentials#domain-credential-17", chars.AsMemory())));
        Assert.Equal(KeyValueSecret, new string(chars, 0, await cache.DecryptAsync("app-credentials", chars.AsMemory())));
        Assert.Equal(0, await cache.DecryptAsync("Missing", new byte[16].AsMemory()));
        Assert.Equal(0, await cache.GetMaxDecryptedLengthAsync("Not:Valid"));

        Assert.Equal(["App-Credentials", "Missing"], vault.Gets);
        Assert.NotEmpty(vault.BodiesSeenBySecretClient);
        Assert.All(vault.BodiesSeenBySecretClient, body => Assert.DoesNotContain("credential", body, StringComparison.Ordinal));
    }

    [Fact]
    public async Task DecryptAsync_PropagatesAKeyVaultFailure()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("Item", "value");
        vault.FailWith = HttpStatusCode.Forbidden;

        var e = await Assert.ThrowsAsync<RequestFailedException>(() => cache.DecryptAsync("Item", new byte[16].AsMemory()).AsTask());
        Assert.Equal(403, e.Status);
    }

    [Fact]
    public async Task AnotherClient_SharingTheOptions_IsLeftAlone_Synchronously()
    {
        var vault = new FakeKeyVault();
        var options = vault.Options();
        _ = new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, new FakeCredential(), await TestRing.CreateAsync(), options);
        vault.Set("Db-Password", "s3cret");

        var client = new SecretClient(FakeKeyVault.VaultUri, new FakeCredential(), options);

        Assert.Equal("s3cret", client.GetSecret("Db-Password").Value.Value);
    }

    [Fact]
    public async Task AnotherClient_SharingTheOptions_IsLeftAlone()
    {
        var vault = new FakeKeyVault();
        var options = vault.Options();
        _ = new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, new FakeCredential(), await TestRing.CreateAsync(), options);
        vault.Set("Db-Password", "s3cret");

        // The cache's policy is now in these options too, but acts only inside the cache's own fetch.
        var client = new SecretClient(FakeKeyVault.VaultUri, new FakeCredential(), options);

        Assert.Equal("s3cret", (await client.GetSecretAsync("Db-Password")).Value.Value);
    }

    [Fact]
    public async Task SecretClient_IsOnlyEverGivenTheBodyWithTheValueBlanked()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("Db-Password", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "Db-Password"));

        var body = Assert.Single(vault.BodiesSeenBySecretClient);
        Assert.DoesNotContain("s3cret", body, StringComparison.Ordinal);
        Assert.Contains("\"value\":\"\"", body, StringComparison.Ordinal);
        // Only the top-level value is taken: a nested property of the same name is left alone.
        Assert.Contains("a tag, not the secret", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AValueWithJsonEscapes_IsUnescapedExactly()
    {
        var (cache, vault) = await CreateAsync();
        const string secret = "p\"a\\ss/wörd\n\u0001秘密";
        vault.Set("escaped", secret);

        Assert.Equal(secret, DecryptString(cache, "escaped"));
        Assert.DoesNotContain("wörd", Assert.Single(vault.BodiesSeenBySecretClient), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_OnMiss_FetchesTheSecret()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("api-key", "value");

        Assert.True(cache.TryGetMaxDecryptedLength("api-key", out var max));
        Assert.True(max >= 5);
        Assert.Equal("value", DecryptString(cache, "api-key"));
        Assert.Single(vault.Gets);
    }

    [Fact]
    public async Task NamesDifferingInCase_AreOneEntry_AndOneFetch()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("Db-Password", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "db-password"));
        Assert.Equal("s3cret", DecryptString(cache, "DB-PASSWORD"));
        Assert.Single(vault.Gets);
    }

    [Fact]
    public async Task AMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists()
    {
        var (cache, vault) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt("later", new byte[16]));
        Assert.False(cache.TryGetMaxDecryptedLength("later", out var max));
        Assert.Equal(0, max);

        vault.Set("later", "now here");
        Assert.Equal("now here", DecryptString(cache, "later"));
        Assert.Equal(3, vault.Gets.Count);
    }

    [Fact]
    public async Task AnEmptySecret_IsReportedMissing()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("empty", "");

        Assert.Equal(0, cache.Decrypt("empty", new byte[16]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("db_password")]
    [InlineData("../keys/other")]
    [InlineData("name/version")]
    [InlineData("name?api-version=1")]
    [InlineData("café")]
    [InlineData("has space")]
    public async Task ANameKeyVaultCantHold_IsMissing_WithoutCallingTheVault(string name)
    {
        var (cache, vault) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.Equal(0, cache.Decrypt(name, new char[16].AsSpan()));
        Assert.False(cache.TryGetMaxDecryptedLength(name, out _));
        Assert.Empty(vault.Gets);
    }

    [Fact]
    public void IsValidSecretName_AcceptsLettersDigitsAndHyphens_UpTo127()
    {
        Assert.True(AzureKeyVaultSecretCache.IsValidSecretName("a"));
        Assert.True(AzureKeyVaultSecretCache.IsValidSecretName("Db-Password-2"));
        Assert.True(AzureKeyVaultSecretCache.IsValidSecretName(new string('x', AzureKeyVaultSecretCache.MaxSecretNameLength)));
        Assert.False(AzureKeyVaultSecretCache.IsValidSecretName(new string('x', AzureKeyVaultSecretCache.MaxSecretNameLength + 1)));
        Assert.False(AzureKeyVaultSecretCache.IsValidSecretName(null));
    }

    [Fact]
    public async Task AVaultFailure_Propagates_AndIsRetriedOnTheNextLookup()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("item", "value");
        vault.FailWith = HttpStatusCode.Forbidden;

        var thrown = Assert.Throws<RequestFailedException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Equal(403, thrown.Status);
        Assert.Equal("Forbidden", thrown.ErrorCode);

        vault.FailWith = null;
        Assert.Equal("value", DecryptString(cache, "item"));
        Assert.Equal(2, vault.Gets.Count);
    }

    [Fact]
    public async Task AResponseThatIsNotJson_IsRefused()
    {
        var (cache, vault) = await CreateAsync();
        vault.RawBody = "not json";

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ACredentialFailure_Propagates()
    {
        var (cache, _) = await CreateAsync(new ThrowingCredential());

        Assert.Throws<AuthenticationFailedException>(() => cache.Decrypt("item", new char[16].AsSpan()));
    }

    [Fact]
    public async Task ConcurrentMissesOnOneName_ShareOneFetch()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("shared", "value");
        using var release = new ManualResetEventSlim();
        vault.OnGet = () => release.Wait(TimeSpan.FromSeconds(10));

        var lookups = Enumerable.Range(0, 8).Select(_ => Task.Run(() => DecryptString(cache, "shared"))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.All(await Task.WhenAll(lookups), value => Assert.Equal("value", value));
        Assert.Single(vault.Gets);
    }

    [Fact]
    public async Task ALargeSecret_RoundTrips()
    {
        var (cache, vault) = await CreateAsync();
        var large = string.Concat(Enumerable.Repeat("é-秘密-", 1500));
        Assert.True(Encoding.UTF8.GetByteCount(large) > ArrayUtility.MaxStackBytes);
        vault.Set("large", large);

        Assert.True(cache.TryGetMaxDecryptedLength("large", out var max));
        var result = new char[max];
        Assert.Equal(large, new string(result, 0, cache.Decrypt("large", result.AsSpan())));
    }

    [Fact]
    public async Task ACachedSecret_StillDecryptsAfterTheRingRotates()
    {
        var vault = new FakeKeyVault();
        await using var ring = await TestRing.CreateAsync();
        var cache = new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, new FakeCredential(), ring, vault.Options());
        vault.Set("before", "v1 value");
        vault.Set("after", "v2 value");

        Assert.Equal("v1 value", DecryptString(cache, "before"));
        ring.Add(2, await TestRing.NewKeyAsync());

        Assert.Equal("v2 value", DecryptString(cache, "after"));
        Assert.Equal("v1 value", DecryptString(cache, "before"));
    }

    [Fact]
    public async Task InACollection_OnlyNamesTheEarlierSourcesMiss_ReachTheVault()
    {
        var (vaultCache, vault) = await CreateAsync();
        vault.Set("from-vault", "vault value");
        var local = new ProtectedCache(await TestRing.CreateAsync());
        local.Add("ConnectionStrings:Admin", "local value".ToCharArray());
        var collection = new ProtectedCacheCollection().Add(local).Add(vaultCache);

        Assert.Equal("local value", DecryptString(collection, "ConnectionStrings:Admin"));
        Assert.Equal("vault value", DecryptString(collection, "from-vault"));
        Assert.Equal(["from-vault"], vault.Gets);
    }

    [Fact]
    public async Task WithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError()
    {
        var logger = new FakeLogger<AzureKeyVaultSecretCache>();
        var (cache, vault) = await CreateAsync(logger: logger);
        vault.Set("item", "never-logged");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("never-logged", DecryptString(cache, "item"));
            vault.FailWith = HttpStatusCode.InternalServerError;
            Assert.Throws<RequestFailedException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("item", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Exception is RequestFailedException);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("never-logged", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OptionsThatLogResponseContent_AreRefused()
    {
        var options = new SecretClientOptions();
        options.Diagnostics.IsLoggingContentEnabled = true;
        var ring = await TestRing.CreateAsync();

        Assert.Throws<ArgumentException>(() => new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, new FakeCredential(), ring, options));
    }

    [Fact]
    public async Task TheDefaultOptions_MakeNoCallUntilASecretIsRequested()
    {
        var cache = new AzureKeyVaultSecretCache(new Uri("https://example.vault.azure.net/"), new DefaultAzureCredential(), await TestRing.CreateAsync());

        // An invalid name never reaches the client, so this needs no network or credential.
        Assert.Equal(0, cache.Decrypt("not:a:secret", new byte[16]));
    }

    [Fact]
    public async Task TheConstructor_RejectsNulls()
    {
        var ring = await TestRing.CreateAsync();
        var credential = new FakeCredential();

        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretCache(null!, credential, ring));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, null!, ring));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretCache(FakeKeyVault.VaultUri, credential, null!));
    }

    private sealed class ThrowingCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new AuthenticationFailedException("no token");

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new AuthenticationFailedException("no token");
    }
}
