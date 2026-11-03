using System.Diagnostics;
using System.Net;
using System.Security.Authentication;
using System.Text;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>Retries, redirects, timeouts, rate limiting and read-your-writes, against a fake Vault.</summary>
public class VaultClientResilienceTests
{
    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.PreconditionFailed)]
    public async Task ARetryableStatus_IsRetried_EachAttemptWithTheTokenAndBody(HttpStatusCode status)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(status).Then(HttpStatusCode.OK, """{"data":{"ok":true}}""");

        var response = await t.Client.WriteAsync("a", new Dictionary<string, object?> { ["k"] = "v" });

        Assert.True(response!.Data!["ok"].GetBoolean());
        Assert.Equal(2, t.Vault.Requests.Count);
        Assert.All(t.Vault.Requests, r => Assert.Equal(FakeVault.Token, r.Header("X-Vault-Token")));
        Assert.All(t.Vault.Requests, r => Assert.Equal("""{"k":"v"}""", r.BodyText));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotImplemented)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task AStatusAnotherAttemptWouldGetToo_IsNotRetried(HttpStatusCode status)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(status, """{"errors":["no"]}""");

        await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("a"));
        Assert.Single(t.Vault.Requests);
    }

    [Fact]
    public async Task OnceRetriesRunOut_TheLastResponseIsTheError()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Respond = _ => FakeVault.Json(HttpStatusCode.ServiceUnavailable, """{"errors":["sealed"]}""");

        var e = await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("a"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, e.StatusCode);
        Assert.Equal(["sealed"], e.Errors);
        Assert.Equal(3, t.Vault.Requests.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task RetryMaxOfZeroOrLess_RetriesNothing(int retryMax)
    {
        using var t = await TestClient.CreateAsync(o => o.Retry.RetryMax = retryMax);
        t.Vault.Respond = _ => FakeVault.Json(HttpStatusCode.InternalServerError, null);

        await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("a"));
        Assert.Single(t.Vault.Requests);
    }

    [Fact]
    public async Task NoAnswer_IsRetried_AndOnceRetriesRunOut_ItsExceptionPropagates()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.ThenThrow(new HttpRequestException("refused")).ThenThrow(new IOException("reset")).ThenThrow(new HttpRequestException("still refused"));

        var e = await Assert.ThrowsAsync<HttpRequestException>(() => t.Client.ReadAsync("a"));

        Assert.Equal("still refused", e.Message);
        Assert.Equal(3, t.Vault.Requests.Count);
    }

    [Fact]
    public async Task ARefusedCertificate_IsNotRetried()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.ThenThrow(new HttpRequestException(HttpRequestError.SecureConnectionError, "untrusted"))
            .ThenThrow(new HttpRequestException("wrapped", new AuthenticationException("untrusted")));

        await Assert.ThrowsAsync<HttpRequestException>(() => t.Client.ReadAsync("a"));
        await Assert.ThrowsAsync<HttpRequestException>(() => t.Client.ReadAsync("b"));
        Assert.Equal(2, t.Vault.Requests.Count);
    }

    [Fact]
    public async Task CustomRetryPolicyAndBackoff_AreUsed()
    {
        var waits = new List<(TimeSpan, TimeSpan, int)>();
        using var t = await TestClient.CreateAsync(o =>
        {
            o.Retry.RetryMax = 5;
            o.Retry.RetryWaitMin = TimeSpan.FromMilliseconds(1);
            o.Retry.RetryWaitMax = TimeSpan.FromMilliseconds(2);
            o.Retry.CheckRetry = (response, _) => response?.StatusCode == HttpStatusCode.NotFound;
            o.Retry.Backoff = (min, max, attempt, _) =>
            {
                waits.Add((min, max, attempt));
                return TimeSpan.FromMilliseconds(-5);
            };
        });
        t.Vault.Then(HttpStatusCode.NotFound).Then(HttpStatusCode.NotFound);

        await t.Client.ReadAsync("a");

        Assert.Equal([(TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(2), 0), (TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(2), 1)], waits);
        Assert.Equal(3, t.Vault.Requests.Count);
    }

    [Fact]
    public async Task Retries_AreLogged_WithoutTheQuery()
    {
        var logger = new ListLogger();
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(VaultClient.TokenPurpose);
        var vault = new FakeVault().Then(HttpStatusCode.BadGateway).ThenThrow(new HttpRequestException("connection reset"));
        using var client = new VaultClient(protector, new VaultClientOptions
        {
            Address = FakeVault.Address,
            HttpMessageHandler = vault,
            Retry = { RetryWaitMin = TimeSpan.Zero, RetryWaitMax = TimeSpan.Zero },
        }, logger);

        await client.ReadAsync("a", new VaultRequestOptions { QueryParameters = [new("secret_id", "s3cret")] });

        Assert.Equal(2, logger.Entries.Count);
        Assert.All(logger.Entries, e => Assert.Contains("/v1/a", e));
        Assert.All(logger.Entries, e => Assert.DoesNotContain("s3cret", e));
        Assert.Contains("502", logger.Entries[0]);
        Assert.Contains("connection reset", logger.Entries[1]);
    }

    [Theory]
    [InlineData(0, 1000, 1000, 1000)]
    [InlineData(1, 1000, 1000, 2000)]
    [InlineData(2, 500, 400, 1500)]
    public void LinearJitterBackoff_IsTheMinTimesTheAttempts_WhenThereIsNoRange(int attempt, int min, int max, int expected)
        => Assert.Equal(TimeSpan.FromMilliseconds(expected),
            VaultRetryOptions.LinearJitterBackoff(TimeSpan.FromMilliseconds(min), TimeSpan.FromMilliseconds(max), attempt, null));

    [Fact]
    public void LinearJitterBackoff_IsBetweenMinAndMax_TimesTheAttempts()
    {
        for (var i = 0; i < 100; i++)
        {
            var wait = VaultRetryOptions.LinearJitterBackoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1.5), 2, null);
            Assert.InRange(wait, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(4.5));
        }
    }

    [Fact]
    public void DefaultRetryPolicy_RetriesAMissingResponse() => Assert.True(VaultRetryOptions.DefaultRetryPolicy(null, null));

    [Fact]
    public async Task ARedirect_FailsByDefault_NamingWhereItPointed()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.TemporaryRedirect, null, ("Location", "https://active.test:8200/v1/a"));

        var e = await Assert.ThrowsAsync<VaultRedirectException>(() => t.Client.ReadAsync("a"));

        Assert.Equal(HttpStatusCode.TemporaryRedirect, e.StatusCode);
        Assert.Equal("redirects are disabled", e.Reason);
        Assert.Equal("307: redirect error: redirects are disabled", e.Message);
        Assert.Equal(new Uri("https://active.test:8200/v1/a"), e.RedirectLocation);
        Assert.Equal(new Uri("https://vault.test:8200/v1/a"), e.RequestUri);
        Assert.Equal(HttpMethod.Get, e.RequestMethod);
        Assert.True(VaultClient.IsErrorStatus(e, HttpStatusCode.TemporaryRedirect));
        Assert.Single(t.Vault.Requests);
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    public async Task FollowRedirects_FollowsOne_WithTheSameMethodBodyAndToken(HttpStatusCode status)
    {
        var logger = new ListLogger();
        using var t = await TestClient.CreateAsync(o => o.FollowRedirects = true);
        using var client = new VaultClient(t.Protector, t.Client.Options, logger);
        t.Vault.Then(status, null, ("Location", "https://active.test:8200/v1/sys/storage/raft/snapshot"))
            .Then(HttpStatusCode.OK, """{"data":{"done":true}}""");

        var response = await client.WriteFromBytesAsync("sys/storage/raft/snapshot", "snapshot"u8.ToArray());

        Assert.True(response!.Data!["done"].GetBoolean());
        var followed = t.Vault.Requests.Last();
        Assert.Equal("https://active.test:8200/v1/sys/storage/raft/snapshot", followed.Uri.ToString());
        Assert.Equal(HttpMethod.Post, followed.Method);
        Assert.Equal("snapshot", followed.BodyText);
        Assert.Equal(FakeVault.Token, followed.Header("X-Vault-Token"));
        Assert.Contains("active.test", Assert.Single(logger.Entries));
    }

    [Fact]
    public async Task ARelativeRedirect_IsResolvedAgainstTheRequest()
    {
        using var t = await TestClient.CreateAsync(o => o.FollowRedirects = true);
        t.Vault.Then(HttpStatusCode.Found, null, ("Location", "/v1/b")).Then(HttpStatusCode.OK, "{}");

        await t.Client.ReadAsync("a");

        Assert.Equal("https://vault.test:8200/v1/b", t.Vault.Requests.Last().Uri.ToString());
    }

    [Fact]
    public async Task ASecondRedirect_Fails()
    {
        using var t = await TestClient.CreateAsync(o => o.FollowRedirects = true);
        t.Vault.Respond = _ => FakeVault.Json(HttpStatusCode.TemporaryRedirect, null, ("Location", "https://loop.test/v1/a"));

        var e = await Assert.ThrowsAsync<VaultRedirectException>(() => t.Client.ReadAsync("a"));

        Assert.Equal("at most one redirect is allowed", e.Reason);
        Assert.Equal(2, t.Vault.Requests.Count);
    }

    [Theory]
    [InlineData("https://vault.test:8200", "http://vault.test:8200/v1/a", false, "the redirect would cause a protocol downgrade")]
    [InlineData("http://127.0.0.1:8200", "http://10.0.0.1:8200/v1/a", false, "the redirect would send the token over unencrypted http")]
    [InlineData("https://vault.test:8200", "ftp://vault.test/v1/a", false, "the redirect would cause a protocol downgrade")]
    [InlineData("http://127.0.0.1:8200", "ftp://vault.test/v1/a", true, "the redirect would send the token over unencrypted http")]
    public async Task ARedirectThatWouldExposeTheToken_Fails(string address, string location, bool allowHttp, string reason)
    {
        using var t = await TestClient.CreateAsync(o =>
        {
            o.Address = new Uri(address);
            o.FollowRedirects = true;
            o.AllowUnencryptedHttp = allowHttp;
        });
        t.Vault.Then(HttpStatusCode.TemporaryRedirect, null, ("Location", location));

        var e = await Assert.ThrowsAsync<VaultRedirectException>(() => t.Client.ReadAsync("a"));

        Assert.Equal(reason, e.Reason);
        Assert.Single(t.Vault.Requests);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8200", "http://localhost:8201/v1/a", false)]
    [InlineData("http://127.0.0.1:8200", "http://10.0.0.1:8200/v1/a", true)]
    public async Task AnHttpRedirect_IsFollowedOnLoopbackOrWhenAllowed(string address, string location, bool allowHttp)
    {
        using var t = await TestClient.CreateAsync(o =>
        {
            o.Address = new Uri(address);
            o.FollowRedirects = true;
            o.AllowUnencryptedHttp = allowHttp;
        });
        t.Vault.Then(HttpStatusCode.TemporaryRedirect, null, ("Location", location));

        await t.Client.ReadAsync("a");

        Assert.Equal(location, t.Vault.Requests.Last().Uri.ToString());
    }

    [Fact]
    public async Task ARedirectWithoutALocation_Fails()
    {
        using var t = await TestClient.CreateAsync(o => o.FollowRedirects = true);
        t.Vault.Then(HttpStatusCode.TemporaryRedirect);

        var e = await Assert.ThrowsAsync<VaultRedirectException>(() => t.Client.ReadAsync("a"));

        Assert.Equal("could not read the redirect location", e.Reason);
        Assert.Null(e.RedirectLocation);
    }

    [Fact]
    public async Task ARequestOutlivingTheTimeout_FailsWithTimeoutException()
    {
        using var t = await TestClient.CreateAsync(o => o.RequestTimeout = TimeSpan.FromMilliseconds(50));
        t.Vault.Delay = TimeSpan.FromSeconds(30);

        var e = await Assert.ThrowsAsync<TimeoutException>(() => t.Client.ReadAsync("a"));

        Assert.IsAssignableFrom<OperationCanceledException>(e.InnerException);
    }

    [Fact]
    public async Task TheCallersCancellation_IsACancellation_NotATimeout()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Delay = TimeSpan.FromSeconds(30);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var e = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => t.Client.ReadAsync("a", cancellationToken: cancel.Token));

        Assert.IsNotType<TimeoutException>(e);
        Assert.Single(t.Vault.Requests);
    }

    [Fact]
    public async Task AZeroTimeout_IsNone()
    {
        using var t = await TestClient.CreateAsync(o => o.RequestTimeout = TimeSpan.Zero);
        t.Vault.Delay = TimeSpan.FromMilliseconds(20);

        Assert.NotNull(await t.Client.ReadAsync("a"));
    }

    [Fact]
    public async Task TheRateLimiter_SpacesRequestsOutOnceTheBurstIsSpent()
    {
        using var t = await TestClient.CreateAsync(o => o.RateLimiter = new VaultRateLimiter(20, 2));
        var watch = Stopwatch.StartNew();

        for (var i = 0; i < 4; i++)
            await t.Client.ReadAsync("a");

        // Two at once, then 50 ms apart.
        Assert.InRange(watch.Elapsed, TimeSpan.FromMilliseconds(80), TimeSpan.FromSeconds(5));
        Assert.Equal(4, t.Vault.Requests.Count);
    }

    [Fact]
    public async Task ARateLimitedRequestCancelled_GivesItsTurnBack()
    {
        var limiter = new VaultRateLimiter(1, 1);
        await limiter.WaitAsync(default);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => limiter.WaitAsync(cancel.Token).AsTask());

        // Had the cancelled request kept its turn, this one would wait two seconds, not one.
        var watch = Stopwatch.StartNew();
        await limiter.WaitAsync(default);
        Assert.InRange(watch.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(1500));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-1, 1)]
    [InlineData(double.NaN, 1)]
    [InlineData(double.PositiveInfinity, 1)]
    [InlineData(1, 0)]
    public void VaultRateLimiter_RefusesWhatIsntALimit(double rate, int burst)
        => Assert.Throws<ArgumentOutOfRangeException>(() => new VaultRateLimiter(rate, burst));

    [Fact]
    public async Task ReadYourWrites_SendsTheStatesSeen_AndAClonesChangeIndependently()
    {
        var state1 = Convert.ToBase64String(Encoding.UTF8.GetBytes("v1:cid:1:0:"));
        var state2 = Convert.ToBase64String(Encoding.UTF8.GetBytes("v1:cid:2:0:"));
        using var t = await TestClient.CreateAsync(o => o.EnforceReadYourWritesConsistency = true);
        t.Vault.Then(HttpStatusCode.OK, "{}", ("X-Vault-Index", state1));

        await t.Client.WriteAsync("a", new Dictionary<string, object?>());
        var clone = t.Client.Clone();
        t.Vault.Then(HttpStatusCode.OK, "{}", ("X-Vault-Index", state2));
        await t.Client.ReadAsync("b");
        await t.Client.ReadAsync("c");
        await clone.ReadAsync("d");

        var requests = t.Vault.Requests.ToArray();
        Assert.Null(requests[0].Header("X-Vault-Index"));
        Assert.Equal(state1, requests[1].Header("X-Vault-Index"));
        Assert.Equal(state2, requests[2].Header("X-Vault-Index"));
        Assert.Equal(state1, requests[3].Header("X-Vault-Index"));
    }

    [Fact]
    public async Task WithoutReadYourWrites_NoStatesAreSent()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, "{}", ("X-Vault-Index", "c3RhdGU="));

        await t.Client.ReadAsync("a");
        await t.Client.ReadAsync("b");

        Assert.All(t.Vault.Requests, r => Assert.Null(r.Header("X-Vault-Index")));
    }

    private sealed class ListLogger : Microsoft.Extensions.Logging.ILogger<VaultClient>
    {
        public List<string> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter) => Entries.Add(formatter(state, exception));
    }
}
