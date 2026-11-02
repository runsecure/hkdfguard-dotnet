using System.Net;
using System.Security.Authentication;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// The rules HashiCorpVaultSecretCache, HashiCorpVaultTransitKeyWrapper and VaultClient share, and the
/// token types that moved here with them. Those packages' own suites test how they use them.
/// </summary>
public class VaultHttpTests
{
    [Theory]
    [InlineData("https://vault.example.com:8200", "https://vault.example.com:8200/v1/")]
    [InlineData("https://vault.example.com:8200/", "https://vault.example.com:8200/v1/")]
    [InlineData("https://vault.example.com/proxy/vault/", "https://vault.example.com/proxy/vault/v1/")]
    [InlineData("http://127.0.0.1:8200", "http://127.0.0.1:8200/v1/")]
    [InlineData("http://localhost:8200", "http://localhost:8200/v1/")]
    public void ApiBase_IsV1UnderTheAddress_KeepingAPrefix(string address, string expected)
        => Assert.Equal(new Uri(expected), VaultHttp.ApiBase(new Uri(address)));

    [Theory]
    [InlineData("http://vault.example.com:8200")]
    [InlineData("ftp://vault.example.com")]
    [InlineData("unix:///var/run/vault.sock")]
    [InlineData("https://user:pass@vault.example.com")]
    [InlineData("https://vault.example.com/?q=1")]
    [InlineData("https://vault.example.com/#f")]
    public void ApiBase_RefusesAnAddressThatWouldExposeTheToken(string address)
        => Assert.Throws<ArgumentException>("address", () => VaultHttp.ApiBase(new Uri(address)));

    [Fact]
    public void ApiBase_RefusesARelativeOrMissingAddress()
    {
        Assert.Throws<ArgumentException>("address", () => VaultHttp.ApiBase(new Uri("/v1", UriKind.Relative)));
        Assert.Throws<ArgumentNullException>("address", () => VaultHttp.ApiBase(null!));
    }

    [Theory]
    [InlineData("secret", true)]
    [InlineData("team-a/my_app/db.v2", true)]
    [InlineData("...x/x..", true)]
    [InlineData("", false)]
    [InlineData("a//b", false)]
    [InlineData("/a", false)]
    [InlineData("a/", false)]
    [InlineData("a/./b", false)]
    [InlineData("a/../b", false)]
    [InlineData("a b", false)]
    [InlineData("a#b", false)]
    [InlineData("café", false)]
    public void IsValidPath_AcceptsOnlyPathsThatStayWhereTheyrePut(string path, bool expected)
        => Assert.Equal(expected, VaultHttp.IsValidPath(path));

    [Theory]
    [InlineData("myapp-kek", true)]
    [InlineData("a/b", false)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("", false)]
    public void IsValidPathSegment_AcceptsOneSegment(string segment, bool expected)
        => Assert.Equal(expected, VaultHttp.IsValidPathSegment(segment));

    [Theory]
    [InlineData("hvs.CAESI", true)]
    [InlineData("!~", true)]
    [InlineData("", false)]
    [InlineData("hvs.with space", false)]
    [InlineData("hvs.line\nbreak", false)]
    [InlineData("café", false)]
    public void IsValidToken_AcceptsWhatCanGoInAHeader(string token, bool expected)
        => Assert.Equal(expected, VaultHttp.IsValidToken(token));

    [Fact]
    public void CreateHandler_FollowsNoRedirects_AndAsksForTls12OrLater()
    {
        using var handler = VaultHttp.CreateHandler();

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(TimeSpan.FromMinutes(5), handler.PooledConnectionLifetime);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, handler.SslOptions.EnabledSslProtocols);
        Assert.False(VaultHttp.FollowsRedirects(handler));
    }

    [Fact]
    public void FollowsRedirects_LooksUnderDelegatingHandlers_AndCountsWhatItCantTellAsNot()
    {
        using var sockets = new SocketsHttpHandler();
        using var client = new HttpClientHandler();
        using var chained = new PassThrough { InnerHandler = new PassThrough { InnerHandler = new SocketsHttpHandler() } };
        using var unchained = new PassThrough();
        using var custom = new FakeVault();

        Assert.True(VaultHttp.FollowsRedirects(sockets));
        Assert.True(VaultHttp.FollowsRedirects(client));
        Assert.True(VaultHttp.FollowsRedirects(chained));
        Assert.False(VaultHttp.FollowsRedirects(unchained));
        Assert.False(VaultHttp.FollowsRedirects(custom));
        Assert.Throws<ArgumentNullException>(() => VaultHttp.FollowsRedirects(null!));
    }

    [Fact]
    public async Task SendWithTokenAsync_SendsTheToken_ThenTakesItOffAndZeroesIt()
    {
        var vault = new FakeVault();
        using var http = new HttpClient(vault);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(FakeVault.Address, "/v1/a"));

        using var response = await VaultHttp.SendWithTokenAsync(http, request, FakeVault.Token.ToCharArray(), default);

        var sent = vault.Single();
        Assert.Equal(FakeVault.Token, sent.Header("X-Vault-Token"));
        Assert.All(sent.TokenHeader!, c => Assert.Equal('\0', c));
        Assert.False(request.Headers.Contains("X-Vault-Token"));
    }

    [Fact]
    public async Task SendWithTokenAsync_ZeroesTheToken_WhenTheSendFails()
    {
        var vault = new FakeVault().ThenThrow(new HttpRequestException("refused"));
        using var http = new HttpClient(vault);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(FakeVault.Address, "/v1/a"));

        await Assert.ThrowsAsync<HttpRequestException>(() => VaultHttp.SendWithTokenAsync(http, request, FakeVault.Token.ToCharArray(), default));

        Assert.All(vault.Single().TokenHeader!, c => Assert.Equal('\0', c));
        Assert.False(request.Headers.Contains("X-Vault-Token"));
    }

    [Fact]
    public async Task SendWithTokenAsync_RefusesWhatIsntAToken_SendingNothing()
    {
        var vault = new FakeVault();
        using var http = new HttpClient(vault);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(FakeVault.Address, "/v1/a"));

        await Assert.ThrowsAsync<ArgumentException>("token", () => VaultHttp.SendWithTokenAsync(http, request, "not a token".ToCharArray(), default));
        await Assert.ThrowsAsync<ArgumentNullException>(() => VaultHttp.SendWithTokenAsync(null!, request, FakeVault.Token.ToCharArray(), default));
        await Assert.ThrowsAsync<ArgumentNullException>(() => VaultHttp.SendWithTokenAsync(http, null!, FakeVault.Token.ToCharArray(), default));
        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task DecryptToken_RevealsAProtectedToken_AndRefusesAnythingElse()
    {
        using var t = await TestClient.CreateAsync();
        var other = (await TestRing.CreateAsync()).CreateProtector(VaultClient.TokenPurpose);

        var token = VaultHttp.DecryptToken(t.Protector, t.Protector.Encrypt(FakeVault.Token), out var length);

        Assert.Equal(FakeVault.Token, new string(token, 0, length));
        Assert.Throws<InvalidOperationException>(() => VaultHttp.DecryptToken(t.Protector, null, out _));
        Assert.Throws<InvalidOperationException>(() => VaultHttp.DecryptToken(t.Protector, "", out _));
        Assert.Throws<InvalidOperationException>(() => VaultHttp.DecryptToken(t.Protector, FakeVault.Token, out _));
        Assert.Throws<InvalidOperationException>(() => VaultHttp.DecryptToken(t.Protector, other.Encrypt(FakeVault.Token), out _));
        Assert.Throws<InvalidOperationException>(() => VaultHttp.DecryptToken(t.Protector, t.Protector.Encrypt("not a token"), out _));
        Assert.Throws<ArgumentNullException>(() => VaultHttp.DecryptToken(null!, "x", out _));
    }

    [Theory]
    [InlineData(200, 0, 0, 200)]
    [InlineData(200, 1, 0, 400)]
    [InlineData(200, 2, 0, 800)]
    [InlineData(200, 2, 50, 850)]
    [InlineData(200, 5, 0, 6400)]
    [InlineData(200, 6, 0, 10_000)]
    [InlineData(200, 20, 0, 10_000)]
    [InlineData(200, 0, 100, 300)]
    [InlineData(200, 9, 100, 10_100)]
    [InlineData(0, 3, 37, 37)]
    [InlineData(10_000, 0, 0, 10_000)]
    public void RetryDelay_Doubles_UpToTheMaximum_PlusTheJitter(int baseMilliseconds, int retry, int jitter, int expectedMilliseconds)
        => Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds),
            VaultHttp.RetryDelay(TimeSpan.FromMilliseconds(baseMilliseconds), retry, jitter));

    [Fact]
    public void MaxRetryDelay_IsTenSeconds() => Assert.Equal(TimeSpan.FromSeconds(10), VaultHttp.MaxRetryDelay);

    public static TheoryData<Exception, bool> Failures => new()
    {
        { new HttpRequestException("no answer"), true },
        { new HttpRequestException("busy", null, HttpStatusCode.TooManyRequests), true },
        { new HttpRequestException("down", null, HttpStatusCode.ServiceUnavailable), true },
        { new HttpRequestException("error", null, HttpStatusCode.InternalServerError), true },
        { new HttpRequestException("not implemented", null, HttpStatusCode.NotImplemented), false },
        { new HttpRequestException("forbidden", null, HttpStatusCode.Forbidden), false },
        { new HttpRequestException("missing", null, HttpStatusCode.NotFound), false },
        { new IOException("reset"), true },
        { new TaskCanceledException("the attempt's own timeout"), true },
        { new InvalidOperationException("a bug"), false },
    };

    [Theory]
    [MemberData(nameof(Failures))]
    public void IsTransient_IsTrueForWhatAnotherAttemptMayNotMeet(Exception failure, bool expected)
        => Assert.Equal(expected, VaultHttp.IsTransient(failure, CancellationToken.None));

    [Fact]
    public void IsTransient_IsFalseForTheCallersOwnCancellation()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.False(VaultHttp.IsTransient(new OperationCanceledException(cancelled.Token), cancelled.Token));
    }

    [Theory]
    [InlineData("""{"errors":["permission denied","2"]}""", new[] { "permission denied", "2" })]
    [InlineData("""{"errors":[1, {"a":true}]}""", new[] { "1", """{"a":true}""" })]
    [InlineData("""{"errors":[]}""", new string[0])]
    [InlineData("""{"data":null}""", new string[0])]
    [InlineData("""{"errors":"one"}""", null)]
    [InlineData("""["x"]""", null)]
    [InlineData("<html>Bad gateway</html>", null)]
    [InlineData("", null)]
    public void ReadErrors_ReadsVaultsErrorList_OrNullForAnythingElse(string body, string[]? expected)
        => Assert.Equal(expected, VaultHttp.ReadErrors(System.Text.Encoding.UTF8.GetBytes(body)));

    [Fact]
    public async Task StaticVaultTokenSource_CopiesItsToken_UntilDisposed()
    {
        var tokens = new StaticVaultTokenSource(FakeVault.Token);
        var destination = new char[VaultHttp.MaxTokenLength];

        var length = await tokens.CopyTokenAsync(destination, default);
        tokens.Dispose();
        var afterDispose = await tokens.CopyTokenAsync(destination, default);

        Assert.Equal(FakeVault.Token.Length, length);
        Assert.Equal(length, afterDispose);
        Assert.All(destination.AsSpan(0, afterDispose).ToArray(), c => Assert.Equal('\0', c));
    }

    [Theory]
    [InlineData("")]
    [InlineData("hvs.with space")]
    [InlineData("hvs.é")]
    public void StaticVaultTokenSource_RejectsATokenThatIsNotOne(string token)
        => Assert.Throws<ArgumentException>("token", () => new StaticVaultTokenSource(token));

    [Fact]
    public async Task StaticVaultTokenSource_RejectsATokenOverTheLimit_AndADestinationTooSmall()
    {
        Assert.Throws<ArgumentException>("token", () => new StaticVaultTokenSource(new string('t', VaultHttp.MaxTokenLength + 1)));
        using var longest = new StaticVaultTokenSource(new string('t', VaultHttp.MaxTokenLength));

        using var tokens = new StaticVaultTokenSource(FakeVault.Token);
        await Assert.ThrowsAsync<ArgumentException>("destination", async () => await tokens.CopyTokenAsync(new char[4], default));
    }

    [Theory]
    [InlineData("")]
    [InlineData("hvs.with space")]
    [InlineData("hvs.line\nbreak")]
    [InlineData("café")]
    public async Task StaticVaultToken_Protect_RejectsATokenThatCantBeSent(string token)
    {
        using var t = await TestClient.CreateAsync();

        Assert.Throws<ArgumentException>(() => StaticVaultToken.Protect(t.Protector, token));
        Assert.Throws<ArgumentNullException>(() => StaticVaultToken.Protect(null!, FakeVault.Token));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void StaticVaultToken_RejectsAnEmptyProtectedToken(string? protectedToken)
        => Assert.ThrowsAny<ArgumentException>(() => new StaticVaultToken(protectedToken!));

    [Fact]
    public async Task StaticVaultToken_Protect_HoldsOnlyTheProtectedToken()
    {
        using var t = await TestClient.CreateAsync();

        var token = StaticVaultToken.Protect(t.Protector, FakeVault.Token);
        var held = await token.GetTokenAsync(CancellationToken.None);

        Assert.DoesNotContain(FakeVault.Token, held, StringComparison.Ordinal);
        Assert.Equal(held, token.ToString());
        Assert.Equal(FakeVault.Token, t.Decrypt(token));
    }

    private sealed class PassThrough : DelegatingHandler;
}
