using System.Net;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.HashiCorpVault.Test.TestHelpers;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.HashiCorpVault.Test;

/// <summary>The cache's real HttpClient against a fake Vault.</summary>
public class HashiCorpVaultSecretCacheTests
{
    private static async Task<(HashiCorpVaultSecretCache Cache, FakeVault Vault)> CreateAsync(
        FakeVault? vault = null, Func<HttpMessageHandler, HashiCorpVaultSecretCacheOptions>? options = null,
        IVaultTokenProvider? tokens = null, Uri? address = null, ILogger<HashiCorpVaultSecretCache>? logger = null)
    {
        vault ??= new FakeVault();
        // No backoff, only each retry's 0-100 ms of jitter, so a test that meets a 5xx stays quick.
        var cacheOptions = options?.Invoke(vault) ?? new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = vault, RetryDelay = TimeSpan.Zero };
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
        if (tokens is FakeTokenProvider fake)
            fake.Protector ??= protector;

        return (new HashiCorpVaultSecretCache(address ?? FakeVault.Address, tokens ?? StaticVaultToken.Protect(protector, FakeVault.Token),
            protector, ring, cacheOptions, logger), vault);
    }

    // A cache on ring, given the fake's token protected for it.
    private static HashiCorpVaultSecretCache NewCache(Uri address, KeyRing ring, HashiCorpVaultSecretCacheOptions? options = null)
    {
        var protector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
        return new HashiCorpVaultSecretCache(address, StaticVaultToken.Protect(protector, FakeVault.Token), protector, ring, options);
    }

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task Decrypt_OnMiss_ReadsTheOneSecret_ThenServesItFromTheCache()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("myapp/Db", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "myapp/Db"));
        var bytes = new byte[64];
        Assert.Equal("s3cret", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("myapp/Db", bytes)));

        Assert.Equal(["myapp/Db"], vault.Reads);
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public async Task TheResponse_IsNeverBufferedByHttpClient()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("item", "s3cret");

        Assert.Equal("s3cret", DecryptString(cache, "item"));
        Assert.Equal(0, cache.Decrypt("missing", new byte[16]));

        Assert.Equal(2, vault.Reads.Count);
        Assert.False(vault.AnyResponseBuffered);
    }

    [Fact]
    public async Task OneRead_CachesEveryKeyTheSecretHolds()
    {
        var (cache, vault) = await CreateAsync();
        vault.SetData("myapp/db", new()
        {
            ["username"] = "app", ["password"] = "s3cret", ["value"] = "default", ["Mixed-Case.key:1"] = "mixed",
        });

        Assert.Equal("s3cret", DecryptString(cache, "myapp/db#password"));
        Assert.Equal("app", DecryptString(cache, "myapp/db#username"));
        Assert.Equal("default", DecryptString(cache, "myapp/db"));
        Assert.Equal("default", DecryptString(cache, "myapp/db#value"));
        Assert.Equal("mixed", DecryptString(cache, "myapp/db#Mixed-Case.key:1"));

        Assert.Equal(["myapp/db"], vault.Reads);
    }

    [Fact]
    public async Task ConcurrentMissesOnDifferentKeys_ShareOneRead()
    {
        var (cache, vault) = await CreateAsync();
        vault.SetData("shared", new() { ["a"] = "1", ["b"] = "2", ["value"] = "3" });
        using var release = new ManualResetEventSlim();
        vault.OnRead = () => release.Wait(TimeSpan.FromSeconds(10));

        var lookups = new[] { "shared#a", "shared#b", "shared" }.Select(name => Task.Run(() => DecryptString(cache, name))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.Equal(["1", "2", "3"], await Task.WhenAll(lookups));
        Assert.Single(vault.Reads);
    }

    [Fact]
    public async Task DecryptAsync_ReadsWithoutBlocking_AndTheResponseIsNeverBuffered()
    {
        var (cache, vault) = await CreateAsync();
        vault.SetData("myapp/db", new() { ["password"] = "s3cret", ["value"] = "default" });

        var chars = new char[64];
        Assert.Equal("s3cret", new string(chars, 0, await cache.DecryptAsync("myapp/db#password", chars.AsMemory())));
        Assert.Equal("default", new string(chars, 0, await cache.DecryptAsync("myapp/db", chars.AsMemory())));
        Assert.Equal(0, await cache.DecryptAsync("missing", new byte[16].AsMemory()));

        Assert.Equal(["myapp/db", "missing"], vault.Reads);
        Assert.False(vault.AnyResponseBuffered);
    }

    [Fact]
    public async Task ACallersCancellation_CancelsTheFetch()
    {
        var tokens = new FakeTokenProvider
        {
            Next = async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return FakeVault.Token;
            },
        };
        var (cache, _) = await CreateAsync(tokens: tokens);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.DecryptAsync("item", new byte[16].AsMemory(), cancel.Token).AsTask());
    }

    [Fact]
    public async Task TheDefaultKey_IsConfigurable()
    {
        var (cache, vault) = await CreateAsync(options: h => new() { HttpMessageHandler = h, DefaultKey = "secret_value" });
        vault.SetData("item", new() { ["value"] = "wrong", ["secret_value"] = "right" });

        Assert.Equal("right", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task KvVersion1_IsReadAtTheMountsOwnPath()
    {
        var vault = new FakeVault { KvVersion = VaultKvVersion.V1, MountPath = "kv" };
        var (cache, _) = await CreateAsync(vault, h => new() { HttpMessageHandler = h, KvVersion = VaultKvVersion.V1, MountPath = "kv" });
        vault.SetData("myapp/db", new() { ["password"] = "v1 value" });

        Assert.Equal("v1 value", DecryptString(cache, "myapp/db#password"));
        Assert.Equal(0, cache.Decrypt("missing", new byte[16]));
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public async Task ANestedMountPath_AndAnAddressPrefix_AreKept()
    {
        var vault = new FakeVault { MountPath = "kv/team-a", PathPrefix = "/vault" };
        var (cache, _) = await CreateAsync(vault, h => new() { HttpMessageHandler = h, MountPath = "kv/team-a" },
            address: new Uri(FakeVault.Address, "/vault/"));
        vault.Set("item", "prefixed");

        Assert.Equal("prefixed", DecryptString(cache, "item"));
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public async Task TheNamespace_IsSent_OnlyWhenSet()
    {
        var (withNamespace, vault) = await CreateAsync(options: h => new() { HttpMessageHandler = h, Namespace = "team-a/prod" });
        var (without, _) = await CreateAsync(vault);
        vault.Set("item", "value");

        DecryptString(withNamespace, "item");
        DecryptString(without, "item");

        Assert.Equal(["team-a/prod", null], vault.Namespaces);
    }

    [Fact]
    public async Task EveryFetch_AsksTheProviderForTheToken()
    {
        var tokens = new FakeTokenProvider();
        var (cache, vault) = await CreateAsync(tokens: tokens);
        vault.Set("a", "1");
        vault.Set("b", "2");

        DecryptString(cache, "a");
        DecryptString(cache, "a");
        DecryptString(cache, "b");

        Assert.Equal(2, tokens.Calls);
        Assert.Equal([FakeVault.Token, FakeVault.Token], vault.Tokens);
    }

    [Fact]
    public async Task ARefusedToken_Propagates403_AndANewTokenIsUsedNextTime()
    {
        var tokens = new FakeTokenProvider { Next = (call, _) => ValueTask.FromResult(call == 1 ? "hvs.expired" : FakeVault.Token) };
        var (cache, vault) = await CreateAsync(tokens: tokens);
        vault.Set("item", "value");

        var e = Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Equal(HttpStatusCode.Forbidden, e.StatusCode);
        Assert.Contains("permission denied", e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hvs.", e.Message, StringComparison.Ordinal);

        Assert.Equal("value", DecryptString(cache, "item"));
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("tab\tinside")]
    [InlineData("café")]
    public async Task ATokenThatCantBeSent_IsRefused_WithoutCallingVault(string token)
    {
        var (cache, vault) = await CreateAsync(tokens: new FakeTokenProvider { Next = (_, _) => ValueTask.FromResult(token) });

        Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Empty(vault.Reads);
    }

    [Theory]
    [InlineData("")]
    [InlineData(FakeVault.Token)]
    [InlineData("enc::v1::not base64!")]
    [InlineData("enc::v1")]
    public async Task AnUnprotectedToken_IsRefused_WithoutCallingVault_OrQuotingIt(string handedOver)
    {
        var (cache, vault) = await CreateAsync(tokens: new FakeTokenProvider { Unprotected = true, Next = (_, _) => ValueTask.FromResult(handedOver) });

        var e = Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Null(e.InnerException);
        if (handedOver.Length > 0)
            Assert.DoesNotContain(handedOver, e.Message, StringComparison.Ordinal);
        Assert.Empty(vault.Reads);
    }

    public static TheoryData<string> ForeignProtections => ["another purpose", "another ring", "a version not on the ring"];

    [Theory]
    [MemberData(nameof(ForeignProtections))]
    public async Task ATokenProtectedWithAnotherKeyOrPurpose_IsRefused_WithoutCallingVault(string how)
    {
        var vault = new FakeVault();
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
        var foreign = how switch
        {
            "another purpose" => ring.CreateProtector("Some.Other.Purpose"),
            "another ring" => (await TestRing.CreateAsync()).CreateProtector(HashiCorpVaultSecretCache.TokenPurpose),
            _ => await RingAtVersion7Async(),
        };
        using var cache = new HashiCorpVaultSecretCache(FakeVault.Address, new StaticVaultToken(foreign.Encrypt(FakeVault.Token)), protector, ring,
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = vault });

        var e = Assert.Throws<InvalidOperationException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Null(e.InnerException);
        Assert.Empty(vault.Reads);

        static async Task<IDataProtector> RingAtVersion7Async()
        {
            var other = new KeyRing(new DefaultFormatProvider());
            other.Add(7, await TestRing.NewKeyAsync());
            return other.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
        }
    }

    [Fact]
    public async Task TheTokenIsDecryptedForEachRequest_AndItsHeaderStringIsZeroedOnceSent()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("a", "1");
        vault.Set("b", "2");

        Assert.Equal("1", DecryptString(cache, "a"));
        Assert.Equal("2", DecryptString(cache, "b"));

        // Vault saw the token in each request...
        Assert.Equal([FakeVault.Token, FakeVault.Token], vault.Tokens);

        // ...and each header's string was zeroed in place once the request had gone.
        Assert.Equal(2, vault.TokenHeaders.Count);
        Assert.All(vault.TokenHeaders, header =>
        {
            Assert.Equal(FakeVault.Token.Length, header.Length);
            Assert.All(header, c => Assert.Equal('\0', c));
        });
    }

    [Fact]
    public async Task ATokenTooLongForTheStack_IsDecryptedIntoPinnedMemory_AndSentWhole()
    {
        var longToken = "hvs." + new string('x', ArrayUtility.MaxStackChars + 100);
        var (cache, vault) = await CreateAsync(tokens: new FakeTokenProvider { Next = (_, _) => ValueTask.FromResult(longToken) });

        // Not the fake's token, so Vault refuses it - after receiving it intact.
        Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Equal([longToken], vault.Tokens);
        Assert.All(Assert.Single(vault.TokenHeaders), c => Assert.Equal('\0', c));
    }

    [Fact]
    public async Task TheTokensHeaderString_IsZeroedEvenWhenTheRequestFails()
    {
        var (cache, vault) = await CreateAsync();
        vault.OnRead = () => throw new HttpRequestException("The connection was reset.");

        Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));

        // One header per attempt - the first and its retries - each zeroed.
        Assert.Equal(1 + HashiCorpVaultSecretCacheOptions.MinRetryCount, vault.TokenHeaders.Count);
        Assert.All(vault.TokenHeaders, header => Assert.All(header, c => Assert.Equal('\0', c)));
    }

    // A cache retrying with no backoff, so only each retry's 0-100 ms of jitter is waited.
    private static Task<(HashiCorpVaultSecretCache Cache, FakeVault Vault)> CreateRetryingAsync(int retryCount = HashiCorpVaultSecretCacheOptions.MinRetryCount,
        FakeTokenProvider? tokens = null)
        => CreateAsync(options: h => new() { HttpMessageHandler = h, RetryCount = retryCount, RetryDelay = TimeSpan.Zero }, tokens: tokens);

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable, """{"errors":["Vault is sealed"]}""")]
    [InlineData(HttpStatusCode.TooManyRequests, """{"errors":["request path \"secret/data/item\": rate limit quota exceeded"]}""")]
    [InlineData(HttpStatusCode.InternalServerError, """{"errors":["internal error"]}""")]
    [InlineData(HttpStatusCode.BadGateway, "<html>Bad Gateway</html>")]
    [InlineData(HttpStatusCode.GatewayTimeout, "")]
    public async Task ATransientAnswer_IsRetried_UntilVaultAnswers(HttpStatusCode status, string body)
    {
        var tokens = new FakeTokenProvider();
        var (cache, vault) = await CreateRetryingAsync(tokens: tokens);
        vault.Set("item", "value");
        vault.Answer = (status, body);
        vault.OnRead = () =>
        {
            if (vault.Reads.Count == 3)
                vault.Answer = null;
        };

        Assert.Equal("value", DecryptString(cache, "item"));

        Assert.Equal(3, vault.Reads.Count);
        Assert.Equal(1, tokens.Calls);
    }

    [Theory]
    [InlineData(HashiCorpVaultSecretCacheOptions.MinRetryCount)]
    [InlineData(HashiCorpVaultSecretCacheOptions.MaxRetryCount)]
    public async Task ATransientAnswer_IsRetriedRetryCountTimes_ThenPropagates(int retryCount)
    {
        var (cache, vault) = await CreateRetryingAsync(retryCount);
        vault.Answer = (HttpStatusCode.ServiceUnavailable, """{"errors":["Vault is sealed"]}""");

        var e = Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, e.StatusCode);
        Assert.Equal(1 + retryCount, vault.Reads.Count);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, """{"errors":["permission denied"]}""")]
    [InlineData(HttpStatusCode.NotFound, """{"errors":["no handler for route"]}""")]
    [InlineData(HttpStatusCode.BadRequest, """{"errors":["bad request"]}""")]
    [InlineData(HttpStatusCode.NotImplemented, """{"errors":["unsupported operation"]}""")]
    [InlineData(HttpStatusCode.TemporaryRedirect, "")]
    public async Task AnAnswerThatWouldRepeat_IsNotRetried(HttpStatusCode status, string body)
    {
        var (cache, vault) = await CreateRetryingAsync();
        vault.Answer = (status, body);

        Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Single(vault.Reads);
    }

    public static TheoryData<string> LostConnections => ["no answer", "dropped mid-response", "attempt timed out"];

    [Theory]
    [MemberData(nameof(LostConnections))]
    public async Task ALostConnection_IsRetried(string how)
    {
        var (cache, vault) = await CreateRetryingAsync();
        vault.Set("item", "value");
        vault.OnRead = () =>
        {
            if (vault.Reads.Count <= 2)
            {
                throw how switch
                {
                    "no answer" => new HttpRequestException("No connection could be made because the target machine actively refused it."),
                    "dropped mid-response" => new IOException("The response ended prematurely."),
                    _ => new TaskCanceledException("The attempt timed out."),
                };
            }
        };

        Assert.Equal("value", DecryptString(cache, "item"));
        Assert.Equal(3, vault.Reads.Count);
    }

    [Fact]
    public async Task TheCallersCancellation_IsNotRetried()
    {
        var (cache, vault) = await CreateRetryingAsync();
        using var cancel = new CancellationTokenSource();
        vault.OnRead = () =>
        {
            cancel.Cancel();
            throw new TaskCanceledException("Cancelled by the caller.");
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.DecryptAsync("item", new byte[16].AsMemory(), cancel.Token).AsTask());
        Assert.Single(vault.Reads);
    }

    [Fact]
    public async Task ATokenProviderFailure_IsNotRetried()
    {
        var tokens = new FakeTokenProvider { Next = (_, _) => throw new HttpRequestException("The login endpoint is unreachable.") };
        var (cache, vault) = await CreateRetryingAsync(tokens: tokens);

        Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));

        Assert.Equal(1, tokens.Calls);
        Assert.Empty(vault.Reads);
    }

    [Theory]
    [InlineData(200, 0, 0, 200)]
    [InlineData(200, 1, 0, 400)]
    [InlineData(200, 2, 0, 800)]
    [InlineData(200, 5, 0, 6400)]
    [InlineData(200, 6, 0, 10_000)]
    [InlineData(200, 9, 0, 10_000)]
    [InlineData(200, 0, 100, 300)]
    [InlineData(200, 9, 100, 10_100)]
    [InlineData(0, 3, 37, 37)]
    [InlineData(10_000, 0, 0, 10_000)]
    public void RetryDelay_Doubles_UpToTheMaximum_PlusTheJitter(int baseMilliseconds, int retry, int jitter, int expectedMilliseconds)
        => Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds),
            HashiCorpVaultSecretCache.RetryDelay(TimeSpan.FromMilliseconds(baseMilliseconds), retry, jitter));

    [Fact]
    public async Task TheRetryOptions_AreChecked()
    {
        var ring = await TestRing.CreateAsync();
        HashiCorpVaultSecretCache Create(HashiCorpVaultSecretCacheOptions options) => NewCache(FakeVault.Address, ring, options);

        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { RetryCount = HashiCorpVaultSecretCacheOptions.MinRetryCount - 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { RetryCount = HashiCorpVaultSecretCacheOptions.MaxRetryCount + 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { RetryDelay = TimeSpan.FromMilliseconds(-1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { RetryDelay = HashiCorpVaultSecretCacheOptions.MaxRetryDelay + TimeSpan.FromTicks(1) }));

        using var fewest = Create(new() { RetryCount = HashiCorpVaultSecretCacheOptions.MinRetryCount, RetryDelay = TimeSpan.Zero });
        using var most = Create(new() { RetryCount = HashiCorpVaultSecretCacheOptions.MaxRetryCount, RetryDelay = HashiCorpVaultSecretCacheOptions.MaxRetryDelay });
    }

    [Fact]
    public async Task ATokenProviderFailure_Propagates()
    {
        var (cache, vault) = await CreateAsync(tokens: new FakeTokenProvider { Next = (_, _) => throw new IOException("The token file can't be read.") });

        Assert.Throws<IOException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Empty(vault.Reads);
    }

    [Fact]
    public async Task AProviderSlowerThanTheTimeout_IsCancelled()
    {
        var tokens = new FakeTokenProvider
        {
            Next = async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return FakeVault.Token;
            },
        };
        var (cache, _) = await CreateAsync(options: h => new() { HttpMessageHandler = h, Timeout = TimeSpan.FromMilliseconds(100) }, tokens: tokens);

        Assert.ThrowsAny<OperationCanceledException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task AValueWithJsonEscapes_IsUnescapedExactly()
    {
        var (cache, vault) = await CreateAsync();
        const string secret = "p\"a\\ss/wörd\n\u0001秘密";
        vault.Set("escaped", secret);

        Assert.Equal(secret, DecryptString(cache, "escaped"));
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
    public async Task PathsDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("myapp/Db", "upper");
        vault.Set("myapp/db", "lower");

        Assert.Equal("upper", DecryptString(cache, "myapp/Db"));
        Assert.Equal("lower", DecryptString(cache, "myapp/db"));
        Assert.Equal(0, cache.Decrypt("MYAPP/DB", new byte[16]));
        Assert.Equal("upper", DecryptString(cache, "myapp/Db"));

        Assert.Equal(["myapp/Db", "myapp/db", "MYAPP/DB"], vault.Reads);
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
        Assert.Equal(3, vault.Reads.Count);
    }

    [Fact]
    public async Task ADeletedLatestVersion_IsReportedMissing()
    {
        var (cache, vault) = await CreateAsync();
        vault.SetDeleted("gone");

        Assert.Equal(0, cache.Decrypt("gone", new byte[16]));
    }

    [Fact]
    public async Task NumbersAndBooleans_AreCachedAsTheirText_AndOtherValuesAreMissing()
    {
        var (cache, vault) = await CreateAsync();
        vault.SetData("item", new()
        {
            ["number"] = 5432, ["flag"] = true, ["empty"] = "", ["object"] = new { value = "nested" }, ["array"] = new[] { "x" }, ["null"] = null,
        });

        Assert.Equal("5432", DecryptString(cache, "item#number"));
        Assert.Equal("true", DecryptString(cache, "item#flag"));
        foreach (var key in new[] { "absent", "empty", "object", "array", "null", "value" })
            Assert.Equal(0, cache.Decrypt($"item#{key}", new byte[16]));
    }

    [Fact]
    public async Task ADuplicatedKey_IsRefused()
    {
        var (cache, vault) = await CreateAsync();
        vault.Answer = (HttpStatusCode.OK, """{"data":{"data":{"k":"a","k":"b"}}}""");

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item#k", new byte[16]));
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, "not json")]
    [InlineData(HttpStatusCode.OK, """["value"]""")]
    [InlineData(HttpStatusCode.OK, """{"data":{"data":{"value":"a","value":"b"}}}""")]
    public async Task AResponseThatCantBeTrusted_IsRefused(HttpStatusCode status, string body)
    {
        var (cache, vault) = await CreateAsync();
        vault.Answer = (status, body);

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, """{"errors":["no handler for route \"nope/data/item\". route entry not found."]}""", "no handler for route")]
    [InlineData(HttpStatusCode.NotFound, "<html>Not Found</html>", "404 NotFound")]
    [InlineData(HttpStatusCode.ServiceUnavailable, """{"errors":["Vault is sealed"]}""", "Vault is sealed")]
    [InlineData(HttpStatusCode.InternalServerError, """["internal"]""", "500 InternalServerError")]
    [InlineData(HttpStatusCode.InternalServerError, """{"errors":"internal"}""", "500 InternalServerError")]
    [InlineData(HttpStatusCode.TemporaryRedirect, "", "307 ")]
    [InlineData(HttpStatusCode.BadGateway, """{"request_id":"x"}""", "502 BadGateway")]
    public async Task AnyOtherAnswer_Propagates_WithVaultsStatusAndErrors(HttpStatusCode status, string body, string expected)
    {
        var (cache, vault) = await CreateAsync();
        vault.Answer = (status, body);

        var e = Assert.Throws<HttpRequestException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Equal(status, e.StatusCode);
        Assert.Contains(expected, e.Message, StringComparison.Ordinal);
        Assert.Contains("'item'", e.Message, StringComparison.Ordinal);

        vault.Answer = null;
        vault.Set("item", "value");
        Assert.Equal("value", DecryptString(cache, "item"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("../sys/seal-status")]
    [InlineData("myapp/../other")]
    [InlineData("myapp/./db")]
    [InlineData("..")]
    [InlineData("/leading")]
    [InlineData("trailing/")]
    [InlineData("double//slash")]
    [InlineData("has space")]
    [InlineData("café")]
    [InlineData("bang!")]
    [InlineData("query?list=true")]
    [InlineData("percent%2F")]
    [InlineData("item#")]
    [InlineData("#key")]
    [InlineData("item#a#b")]
    [InlineData("item#a b")]
    [InlineData("item#bang!")]
    public async Task ANameThatIsntAPathAndKey_IsMissing_WithoutCallingVault(string name)
    {
        var (cache, vault) = await CreateAsync();

        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.Equal(0, cache.Decrypt(name, new char[16].AsSpan()));
        Assert.False(cache.TryGetMaxDecryptedLength(name, out var max));
        Assert.Equal(0, max);
        Assert.Empty(vault.Reads);
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public void IsValidSecretName_AcceptsPathsAndKeys_UpToTheLimit()
    {
        Assert.True(HashiCorpVaultSecretCache.IsValidSecretName("a"));
        Assert.True(HashiCorpVaultSecretCache.IsValidSecretName("team-a/my_app/db.v2"));
        Assert.True(HashiCorpVaultSecretCache.IsValidSecretName("...x/x.."));
        Assert.False(HashiCorpVaultSecretCache.IsValidSecretName("myapp/db#password"));
        Assert.True(HashiCorpVaultSecretCache.IsValidSecretName(new string('x', HashiCorpVaultSecretCache.MaxSecretNameLength)));
        Assert.False(HashiCorpVaultSecretCache.IsValidSecretName(new string('x', HashiCorpVaultSecretCache.MaxSecretNameLength + 1)));
        Assert.False(HashiCorpVaultSecretCache.IsValidSecretName(null));
    }

    [Fact]
    public async Task ConcurrentMissesOnOneName_ShareOneFetch()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("shared", "value");
        using var release = new ManualResetEventSlim();
        vault.OnRead = () => release.Wait(TimeSpan.FromSeconds(10));

        var lookups = Enumerable.Range(0, 8).Select(_ => Task.Run(() => DecryptString(cache, "shared"))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.All(await Task.WhenAll(lookups), value => Assert.Equal("value", value));
        Assert.Single(vault.Reads);
    }

    [Fact]
    public async Task ACachedSecret_StillDecryptsAfterTheRingRotates()
    {
        var vault = new FakeVault();
        await using var ring = await TestRing.CreateAsync();
        using var cache = NewCache(FakeVault.Address, ring,
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = vault });
        vault.Set("before", "v1 value");
        vault.Set("after", "v2 value");

        Assert.Equal("v1 value", DecryptString(cache, "before"));
        ring.Add(2, await TestRing.NewKeyAsync());

        Assert.Equal("v2 value", DecryptString(cache, "after"));
        Assert.Equal("v1 value", DecryptString(cache, "before"));
    }

    [Fact]
    public async Task InACollection_OnlyNamesTheEarlierSourcesMiss_ReachVault()
    {
        var (vaultCache, vault) = await CreateAsync();
        vault.Set("from-vault", "vault value");
        var local = new ProtectedCache(await TestRing.CreateAsync());
        local.Add("ConnectionStrings:Admin", "local value".ToCharArray());
        var collection = new ProtectedCacheCollection().Add(local).Add(vaultCache);

        Assert.Equal("local value", DecryptString(collection, "ConnectionStrings:Admin"));
        Assert.Equal("vault value", DecryptString(collection, "from-vault"));
        Assert.Equal(["from-vault"], vault.Reads);
    }

    [Fact]
    public async Task WithSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError()
    {
        var logger = new FakeLogger<HashiCorpVaultSecretCache>();
        var (cache, vault) = await CreateAsync(logger: logger);
        vault.Set("myapp/Item", "never-logged");

        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
            Assert.Equal("never-logged", DecryptString(cache, "myapp/Item"));
            vault.Answer = (HttpStatusCode.ServiceUnavailable, """{"errors":["Vault is sealed"]}""");
            Assert.Throws<HttpRequestException>(() => cache.Decrypt("other", new byte[16]));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }

        // The secret's own name, not its escaped entry name.
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Message.Contains("myapp/Item", StringComparison.Ordinal));
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Error && e.Exception is HttpRequestException);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains("never-logged", StringComparison.Ordinal)
                                                   || e.Message.Contains(FakeVault.Token, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Dispose_LeavesTheCallersHandlerUsable()
    {
        var (cache, vault) = await CreateAsync();
        vault.Set("item", "value");
        cache.Dispose();

        using var client = new HttpClient(vault);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(FakeVault.Address, "/v1/secret/data/item"));
        request.Headers.Add("X-Vault-Request", "true");
        request.Headers.Add("X-Vault-Token", FakeVault.Token);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task TheDefaults_MakeNoCallUntilASecretIsRequested()
    {
        using var cache = NewCache(new Uri("http://127.0.0.1:8200"), await TestRing.CreateAsync());

        Assert.Equal(0, cache.Decrypt("not:a:path", new byte[16]));
    }

    [Theory]
    [InlineData("relative/path")]
    [InlineData("vault.test:8200")]
    [InlineData("http://vault.example.com:8200")]
    [InlineData("ftp://127.0.0.1")]
    [InlineData("https://user:pass@vault.example.com")]
    [InlineData("https://vault.example.com/?x=1")]
    [InlineData("https://vault.example.com/#frag")]
    public async Task TheConstructor_RejectsAnAddressThatWouldExposeTheToken(string address)
    {
        var ring = await TestRing.CreateAsync();

        Assert.Throws<ArgumentException>(() => NewCache(new Uri(address, UriKind.RelativeOrAbsolute), ring));
    }

    [Fact]
    public async Task TheConstructor_RejectsInvalidOptions()
    {
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
        var token = StaticVaultToken.Protect(protector, FakeVault.Token);
        HashiCorpVaultSecretCache Create(HashiCorpVaultSecretCacheOptions options) => new(FakeVault.Address, token, protector, ring, options);

        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretCache(null!, token, protector, ring));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretCache(FakeVault.Address, null!, protector, ring));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretCache(FakeVault.Address, token, null!, ring));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretCache(FakeVault.Address, token, protector, null!));
        Assert.Throws<ArgumentException>(() => Create(new() { MountPath = "" }));
        Assert.Throws<ArgumentException>(() => Create(new() { MountPath = "../sys" }));
        Assert.Throws<ArgumentException>(() => Create(new() { MountPath = null! }));
        Assert.Throws<ArgumentException>(() => Create(new() { DefaultKey = "" }));
        Assert.Throws<ArgumentException>(() => Create(new() { DefaultKey = "a b" }));
        Assert.Throws<ArgumentException>(() => Create(new() { Namespace = "team a" }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { KvVersion = (VaultKvVersion)3 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(new() { Timeout = TimeSpan.Zero }));
    }

    public static TheoryData<string> RedirectingHandlers => ["sockets", "client", "wrapped"];

    // A handler of each kind, with its default AllowAutoRedirect (true) unless redirects is given.
    private static HttpMessageHandler Handler(string kind, bool? redirects = null) => kind switch
    {
        "sockets" => new SocketsHttpHandler { AllowAutoRedirect = redirects ?? true },
        "client" => new HttpClientHandler { AllowAutoRedirect = redirects ?? true },
        _ => new PassThrough(new PassThrough(Handler("sockets", redirects))),
    };

    [Theory]
    [MemberData(nameof(RedirectingHandlers))]
    public async Task AHandlerThatFollowsRedirects_IsRefused(string kind)
    {
        var ring = await TestRing.CreateAsync();
        using var handler = Handler(kind);

        var e = Assert.Throws<ArgumentException>(() => NewCache(FakeVault.Address, ring,
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = handler }));
        Assert.Contains("AllowRedirects", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(RedirectingHandlers))]
    public async Task AHandlerThatFollowsNoRedirects_IsAccepted(string kind)
    {
        using var handler = Handler(kind, redirects: false);
        using var cache = NewCache(FakeVault.Address, await TestRing.CreateAsync(),
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = handler });

        Assert.Equal(0, cache.Decrypt("not:a:path", new byte[16]));
    }

    [Theory]
    [MemberData(nameof(RedirectingHandlers))]
    public async Task AHandlerThatFollowsRedirects_IsAccepted_WhenExplicitlyAllowed(string kind)
    {
        using var handler = Handler(kind);
        using var cache = NewCache(FakeVault.Address, await TestRing.CreateAsync(),
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = handler, AllowRedirects = true });

        Assert.Equal(0, cache.Decrypt("not:a:path", new byte[16]));
    }

    [Fact]
    public async Task ADelegatingHandlerWithNoInnerHandler_OrOfAnotherType_CantBeChecked_AndIsAccepted()
    {
        var ring = await TestRing.CreateAsync();
        using var unchained = new PassThrough(null);
        using var custom = new FakeVault();

        using var first = NewCache(FakeVault.Address, ring,
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = unchained });
        using var second = NewCache(FakeVault.Address, ring,
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = custom });
    }

    private sealed class PassThrough : DelegatingHandler
    {
        public PassThrough(HttpMessageHandler? inner)
        {
            if (inner is not null)
                InnerHandler = inner;
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("hvs.with space")]
    [InlineData("hvs.line\nbreak")]
    [InlineData("caf\u00e9")]
    public async Task StaticVaultToken_Protect_RejectsATokenThatCantBeSent(string token)
    {
        var protector = (await TestRing.CreateAsync()).CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);

        Assert.Throws<ArgumentException>(() => StaticVaultToken.Protect(protector, token));
    }

    [Fact]
    public void StaticVaultToken_Protect_RejectsANullProtector()
        => Assert.Throws<ArgumentNullException>(() => StaticVaultToken.Protect(null!, FakeVault.Token));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void StaticVaultToken_RejectsAnEmptyProtectedToken(string? protectedToken)
        => Assert.ThrowsAny<ArgumentException>(() => new StaticVaultToken(protectedToken!));

    [Fact]
    public async Task StaticVaultToken_Protect_HoldsOnlyTheProtectedToken()
    {
        var protector = (await TestRing.CreateAsync()).CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);

        var held = await StaticVaultToken.Protect(protector, FakeVault.Token).GetTokenAsync(CancellationToken.None);

        Assert.DoesNotContain(FakeVault.Token, held, StringComparison.Ordinal);
        var token = new char[64];
        Assert.Equal(FakeVault.Token, new string(token, 0, protector.Decrypt(held, token)));
    }
}
