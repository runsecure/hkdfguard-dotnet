using System.Net;
using System.Text;
using System.Text.Json;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>The client's requests and responses, against a fake Vault: vault-client-go's client, request and response tests, and the token handling it doesn't have.</summary>
public class VaultClientTests
{
    [Theory]
    [InlineData("/v1/path/to/a", "/v1/path/to/a")]
    [InlineData("v1/path/to/a", "/v1/path/to/a")]
    [InlineData("/path/to/a", "/v1/path/to/a")]
    [InlineData("path/to/a", "/v1/path/to/a")]
    public void V1Path_PrefixesPathsWithV1(string path, string expected) => Assert.Equal(expected, VaultClient.V1Path(path));

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("/")]
    [InlineData("v1")]
    [InlineData("//x/v1/")]
    public void V1Path_AlwaysStartsWithV1_AndEndsWithThePath(string path)
    {
        var formatted = VaultClient.V1Path(path);
        Assert.StartsWith("/v1/", formatted);
        Assert.EndsWith(path, formatted);
    }

    [Fact]
    public async Task ReadAsync_GetsThePath_WithTheTokenAndClientHeaders()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, """{"request_id":"r1","data":{"key1":"value1","n":12}}""");

        var response = await t.Client.ReadAsync("secret/foo");

        var request = t.Vault.Single();
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://vault.test:8200/v1/secret/foo", request.Uri.ToString());
        Assert.Equal(FakeVault.Token, request.Header("X-Vault-Token"));
        Assert.Equal("true", request.Header("X-Vault-Request"));
        Assert.StartsWith("HkdfGuard.Integration.HashiCorpVault/", request.Header("User-Agent"));
        Assert.Null(request.Body);

        Assert.Equal("r1", response!.RequestId);
        Assert.Equal("value1", response.Data!["key1"].GetString());
        Assert.Equal(12, response.Data["n"].GetInt32());
    }

    [Fact]
    public async Task TheTokenHeader_IsZeroedOnceSent_AndCallbacksNeverSeeIt()
    {
        string? seenByRequestCallback = "unset", seenByResponseCallback = "unset";
        using var t = await TestClient.CreateAsync();
        t.Client.SetRequestCallbacks(r => seenByRequestCallback = r.Headers.NonValidated.Contains("X-Vault-Token") ? "present" : null);
        t.Client.SetResponseCallbacks((r, _) => seenByResponseCallback = r.Headers.NonValidated.Contains("X-Vault-Token") ? "present" : null);

        await t.Client.ReadAsync("secret/foo");

        var header = t.Vault.Single().TokenHeader!;
        Assert.Equal(FakeVault.Token.Length, header.Length);
        Assert.All(header, c => Assert.Equal('\0', c));
        Assert.Null(seenByRequestCallback);
        Assert.Null(seenByResponseCallback);
    }

    [Fact]
    public async Task WithoutAToken_NoTokenHeaderIsSent()
    {
        using var t = await TestClient.CreateAsync(withToken: false);

        await t.Client.ReadAsync("sys/seal-status");

        Assert.Null(t.Vault.Single().Header("X-Vault-Token"));
    }

    [Fact]
    public async Task SetToken_ProtectsIt_AndARequestsOwnTokenWins()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Client.SetToken("hvs.client-token");
        await t.Client.ReadAsync("a");
        await t.Client.ReadAsync("b", new VaultRequestOptions { Token = t.Client.ProtectToken("hvs.request-token") });
        t.Client.ClearToken();
        await t.Client.ReadAsync("c");

        Assert.Equal(["hvs.client-token", "hvs.request-token", null], t.Vault.Requests.Select(r => r.Header("X-Vault-Token")));
    }

    [Fact]
    public async Task AnUnprotectedToken_FailsTheRequest_WithoutQuotingIt()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Client.SetToken(new StaticVaultToken("hvs.plaintext-token"));

        var e = await Assert.ThrowsAsync<InvalidOperationException>(() => t.Client.ReadAsync("secret/foo"));

        Assert.DoesNotContain("plaintext", e.Message);
        Assert.Null(e.InnerException);
        Assert.Empty(t.Vault.Requests);
    }

    [Fact]
    public async Task AProviderReturningNoToken_FailsTheRequest()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Client.SetToken(new EmptyTokenProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(() => t.Client.ReadAsync("secret/foo"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("tab\t")]
    [InlineData("non-ascii-é")]
    public async Task ProtectToken_RefusesWhatCantGoInAHeader(string token)
    {
        using var t = await TestClient.CreateAsync();
        Assert.Throws<ArgumentException>(() => t.Client.ProtectToken(token));
    }

    [Fact]
    public async Task ATokenProtectedForSomethingElse_FailsTheRequest()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        var ring = await TestRing.CreateAsync();
        t.Client.SetToken(StaticVaultToken.Protect(ring.CreateProtector(VaultClient.TokenPurpose), "hvs.other-ring"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => t.Client.ReadAsync("secret/foo"));
    }

    [Fact]
    public async Task AnAddressPath_IsKeptAsAPrefix()
    {
        using var t = await TestClient.CreateAsync(o => o.Address = new Uri("https://vault.test:8200/proxy/vault/"));

        await t.Client.ReadAsync("secret/foo");

        Assert.Equal("/proxy/vault/v1/secret/foo", t.Vault.Single().PathAndQuery);
    }

    [Fact]
    public async Task Namespace_FromOptions_IsOverriddenPerRequest_AndCleared()
    {
        using var t = await TestClient.CreateAsync(o => o.Namespace = "ns1");
        await t.Client.ReadAsync("a");
        await t.Client.ReadAsync("b", new VaultRequestOptions { Namespace = "ns2" });
        await t.Client.ReadAsync("c", new VaultRequestOptions { Namespace = "" });
        t.Client.SetNamespace("ns3/child");
        await t.Client.ReadAsync("d");
        t.Client.SetNamespace("");
        await t.Client.ReadAsync("e");
        t.Client.SetNamespace("ns4");
        t.Client.ClearNamespace();
        await t.Client.ReadAsync("f");

        Assert.Equal(["ns1", "ns2", "ns1", "ns3/child", null, null], t.Vault.Requests.Select(r => r.Header("X-Vault-Namespace")));
        Assert.Throws<ArgumentException>(() => t.Client.SetNamespace("bad​"));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ReadAsync("g", new VaultRequestOptions { Namespace = "bad\n" }));
    }

    [Fact]
    public async Task MfaCredentials_AreAppended_ClientsFirst()
    {
        using var t = await TestClient.CreateAsync();
        t.Client.SetMfaCredentials("m1:111");
        await t.Client.ReadAsync("a", new VaultRequestOptions { MfaCredentials = ["m2:222"] });
        t.Client.ClearMfaCredentials();
        await t.Client.ReadAsync("b");

        var requests = t.Vault.Requests.ToArray();
        Assert.Equal(["m1:111", "m2:222"], requests[0].Headers["X-Vault-MFA"]);
        Assert.Null(requests[1].Header("X-Vault-MFA"));
        Assert.Throws<ArgumentException>(() => t.Client.SetMfaCredentials(""));
    }

    [Fact]
    public async Task ResponseWrapping_SendsTheTtlAsAGoDuration_RequestsOverridingTheClient()
    {
        using var t = await TestClient.CreateAsync();
        t.Client.SetResponseWrapping(TimeSpan.FromMinutes(5));
        await t.Client.ReadAsync("a");
        await t.Client.ReadAsync("b", new VaultRequestOptions { ResponseWrappingTtl = TimeSpan.FromSeconds(90) });
        await t.Client.ReadAsync("c", new VaultRequestOptions { ResponseWrappingTtl = TimeSpan.Zero });
        t.Client.ClearResponseWrapping();
        await t.Client.ReadAsync("d");

        Assert.Equal(["5m0s", "1m30s", "5m0s", null], t.Vault.Requests.Select(r => r.Header("X-Vault-Wrap-TTL")));
        Assert.Throws<ArgumentOutOfRangeException>(() => t.Client.SetResponseWrapping(TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public async Task ReplicationForwardingMode_SendsItsHeader()
    {
        using var t = await TestClient.CreateAsync();
        t.Client.SetReplicationForwardingMode(ReplicationForwardingMode.Always);
        await t.Client.ReadAsync("a");
        await t.Client.ReadAsync("b", new VaultRequestOptions { ReplicationForwardingMode = ReplicationForwardingMode.Inconsistent });
        t.Client.ClearReplicationForwardingMode();
        await t.Client.ReadAsync("c");

        var requests = t.Vault.Requests.ToArray();
        Assert.Equal("active-node", requests[0].Header("X-Vault-Forward"));
        Assert.Null(requests[0].Header("X-Vault-Inconsistent"));
        Assert.Equal("forward-active-node", requests[1].Header("X-Vault-Inconsistent"));
        Assert.Null(requests[1].Header("X-Vault-Forward"));
        Assert.Null(requests[2].Header("X-Vault-Forward"));
        Assert.Null(requests[2].Header("X-Vault-Inconsistent"));
        Assert.Throws<ArgumentOutOfRangeException>(() => t.Client.SetReplicationForwardingMode((ReplicationForwardingMode)7));
    }

    [Fact]
    public async Task CustomHeaders_RequestsReplaceSameNamedOnes_AndKeepTheRest()
    {
        using var t = await TestClient.CreateAsync();
        t.Client.SetCustomHeaders(new Dictionary<string, IReadOnlyList<string>> { ["x-a"] = ["hi"], ["x-b"] = ["client"] });
        await t.Client.ReadAsync("a", new VaultRequestOptions
        {
            CustomHeaders = new Dictionary<string, IReadOnlyList<string>> { ["X-B"] = ["request"], ["x-c"] = ["1", "2"] },
        });
        t.Client.ClearCustomHeaders();
        await t.Client.ReadAsync("b");

        var requests = t.Vault.Requests.ToArray();
        Assert.Equal("hi", requests[0].Header("x-a"));
        Assert.Equal("request", requests[0].Header("x-b"));
        Assert.Equal(["1", "2"], requests[0].Headers["x-c"]);
        Assert.Null(requests[1].Header("x-a"));
    }

    [Theory]
    [InlineData("x-vault-something")]
    [InlineData("X-Vault-Something")]
    [InlineData(" ")]
    public async Task CustomHeaders_RefuseTheClientsOwnPrefix(string name)
    {
        using var t = await TestClient.CreateAsync();
        var headers = new Dictionary<string, IReadOnlyList<string>> { ["a"] = ["b"], [name] = ["d"] };

        Assert.Throws<ArgumentException>(() => t.Client.SetCustomHeaders(headers));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ReadAsync("a", new VaultRequestOptions { CustomHeaders = headers }));
        Assert.Empty(t.Vault.Requests);
    }

    [Fact]
    public async Task ACustomContentHeader_GoesOnTheBody()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.WriteFromBytesAsync("a", "<p/>"u8.ToArray(), new VaultRequestOptions
        {
            CustomHeaders = new Dictionary<string, IReadOnlyList<string>> { ["Content-Type"] = ["text/html"] },
        });

        Assert.Equal("text/html", t.Vault.Single().Header("Content-Type"));
    }

    [Fact]
    public async Task ACustomContentHeader_IsDropped_WithoutABody()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.ReadAsync("a", new VaultRequestOptions
        {
            CustomHeaders = new Dictionary<string, IReadOnlyList<string>> { ["Content-Type"] = ["text/html"] },
        });

        Assert.Null(t.Vault.Single().Header("Content-Type"));
    }

    [Fact]
    public async Task ALongToken_IsHandledInPinnedMemory_BothWays()
    {
        var longToken = "hvs." + new string('x', 3000);
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Vault.Then(HttpStatusCode.OK, """{"data":null,"auth":{"client_token":""" + "\"" + longToken + "\"}}");

        var login = await t.Client.WriteAsync("auth/userpass/login/u", new Dictionary<string, object?> { ["password"] = "p" });
        t.Client.SetToken(login!.Auth!.ClientToken!);
        await t.Client.ReadAsync("a");

        Assert.Equal(longToken, t.Vault.Requests.Last().Header("X-Vault-Token"));
    }

    [Fact]
    public async Task AProtectedValueThatIsntAToken_FailsTheRequest()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Client.SetToken(new StaticVaultToken(t.Protector.Encrypt("not a token")));

        await Assert.ThrowsAsync<InvalidOperationException>(() => t.Client.ReadAsync("a"));
        Assert.Empty(t.Vault.Requests);
    }

    [Theory]
    [InlineData("[1]")]
    [InlineData("""{"a":""")]
    [InlineData("not json")]
    public async Task AResponseThatIsntAJsonObject_FailsWithJsonException(string body)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, body);

        await Assert.ThrowsAnyAsync<JsonException>(() => t.Client.ReadAsync("a"));
    }

    [Fact]
    public async Task QueryParameters_AreSortedByName_AndEscaped_AndListAddsListTrue()
    {
        using var t = await TestClient.CreateAsync();
        var options = new VaultRequestOptions { QueryParameters = [new("z", "1"), new("a", "x y&z"), new("z", "0")] };
        await t.Client.ReadAsync("a", options);
        await t.Client.ListAsync("b", options);
        await t.Client.DeleteAsync("c", options);

        Assert.Equal(["/v1/a?a=x%20y%26z&z=1&z=0", "/v1/b?a=x%20y%26z&list=true&z=1&z=0", "/v1/c?a=x%20y%26z&z=1&z=0"],
            t.Vault.Requests.Select(r => r.PathAndQuery));
        Assert.Equal([HttpMethod.Get, HttpMethod.Get, HttpMethod.Delete], t.Vault.Requests.Select(r => r.Method));
    }

    [Fact]
    public async Task WriteAsync_PostsTheBodyAsJson()
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.WriteAsync("secret/data/foo", new Dictionary<string, object?>
        {
            ["data"] = new Dictionary<string, object?> { ["password1"] = "abc123", ["n"] = 3 },
            ["none"] = null,
        });

        var request = t.Vault.Single();
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("""{"data":{"password1":"abc123","n":3},"none":null}""", request.BodyText);
    }

    [Fact]
    public async Task WriteFromBytesAndStream_PostTheBodyAsItIs()
    {
        using var t = await TestClient.CreateAsync();
        await t.Client.WriteFromBytesAsync("a", "{raw}"u8.ToArray());
        await t.Client.WriteFromStreamAsync("b", new MemoryStream("{streamed}"u8.ToArray()));
        await t.Client.WriteFromStreamAsync("c", new NonSeekableStream(new byte[100_000]));

        var requests = t.Vault.Requests.ToArray();
        Assert.Equal("{raw}", requests[0].BodyText);
        Assert.Equal("{streamed}", requests[1].BodyText);
        Assert.Equal(100_000, requests[2].Body!.Length);
    }

    [Theory]
    [InlineData("", false, null)]
    [InlineData("{}", true, 0)]
    [InlineData("""{"data":{"key1":"value1","key2":"value2"}}""", true, 2)]
    [InlineData("""{"key1":"value1","key2":"value2"}""", true, 2)]
    public async Task Responses_AreTheEnvelope_OrWholeAsData_OrNullWhenEmpty(string body, bool expectResponse, int? expectedKeys)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, body);

        var response = await t.Client.ReadAsync("a");

        Assert.Equal(expectResponse, response is not null);
        Assert.Equal(expectedKeys, response?.Data?.Count);
        if (expectedKeys == 2)
            Assert.Equal("value2", response!.Data!["key2"].GetString());
    }

    [Theory]
    [InlineData("""{"data":{"test_string":"test","test_bool":true}}""", "test", true)]
    [InlineData("""{"test_string":"test","test_bool":false}""", "test", false)]
    [InlineData("{}", null, false)]
    public async Task StructuredResponses_AreReadIntoTheirType(string body, string? expectedString, bool expectedBool)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, body);

        var response = await t.Client.SendAsync<TestStruct>(HttpMethod.Get, "/v1/a", null, null, null, default);

        Assert.Equal(expectedString, response!.Data!.TestString);
        Assert.Equal(expectedBool, response.Data.TestBool);
    }

    [Fact]
    public async Task TheEnvelope_IsReadWhole()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, """
            {"request_id":"r","lease_id":"l","lease_duration":3600,"renewable":true,"data":null,"warnings":["w1"],
             "auth":{"client_token":"hvs.login-token","accessor":"acc","policies":["default"],"token_policies":["default"],
                     "identity_policies":[],"metadata":{"role":"r1"},"orphan":true,"entity_id":"e","lease_duration":60,"renewable":true,
                     "mfa_requirement":{"mfa_request_id":"m","mfa_constraints":{"c":{"any":[{"type":"totp","id":"i","uses_passcode":true}]}}}},
             "wrap_info":null}
            """);

        var response = (await t.Client.ReadAsync("a"))!;

        Assert.Equal(("r", "l", 3600L, true, null, "w1"), (response.RequestId, response.LeaseId, response.LeaseDuration, response.Renewable, response.Data, response.Warnings!.Single()));
        var auth = response.Auth!;
        Assert.Equal(("acc", "default", "r1", true, "e", 60L, true), (auth.Accessor, auth.Policies!.Single(), auth.Metadata!["role"], auth.Orphan, auth.EntityId, auth.LeaseDuration, auth.Renewable));
        Assert.Equal(["default"], auth.TokenPolicies!);
        Assert.Empty(auth.IdentityPolicies!);
        var method = auth.MfaRequirement!.MfaConstraints!["c"].Any!.Single();
        Assert.Equal(("m", "totp", "i", true), (auth.MfaRequirement.MfaRequestId, method.Type, method.Id, method.UsesPasscode));
    }

    [Fact]
    public async Task ALoginsToken_IsProtectedAsItIsRead_AndCanBeSetAsTheClientsToken()
    {
        using var t = await TestClient.CreateAsync(withToken: false);
        t.Vault.Then(HttpStatusCode.OK, """{"auth":{"client_token":"hvs.issued-by-login","accessor":"a"}}""");

        var login = await t.Client.Auth.AppRoleLoginAsync(new Schema.AppRoleLoginRequest { RoleId = "role", SecretId = "secret" });
        var token = login!.Auth!.ClientToken!;
        t.Client.SetToken(token);
        await t.Client.ReadAsync("secret/foo");

        Assert.DoesNotContain("issued-by-login", token.ToString());
        Assert.Equal("hvs.issued-by-login", t.Decrypt(token));
        var requests = t.Vault.Requests.ToArray();
        Assert.Equal("/v1/auth/approle/login", requests[0].PathAndQuery);
        Assert.Equal("""{"role_id":"role","secret_id":"secret"}""", requests[0].BodyText);
        Assert.Equal("hvs.issued-by-login", requests[1].Header("X-Vault-Token"));
    }

    [Theory]
    [InlineData("""{"auth":{"client_token":""}}""")]
    [InlineData("""{"auth":{"client_token":null}}""")]
    [InlineData("""{"auth":{}}""")]
    public async Task NoLoginToken_IsNull(string body)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, body);

        Assert.Null((await t.Client.ReadAsync("a"))!.Auth!.ClientToken);
    }

    [Theory]
    [InlineData("""{"auth":{"client_token":"has space"}}""")]
    [InlineData("""{"auth":{"client_token":12}}""")]
    public async Task ALoginTokenThatIsntOne_FailsTheResponse(string body)
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, body);

        await Assert.ThrowsAsync<JsonException>(() => t.Client.ReadAsync("a"));
    }

    [Fact]
    public async Task UnwrapAsync_PutsWithTheWrappingToken_AndReadsTheWrappedResponse()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.OK, """
            {"wrap_info":{"token":"hvs.wrapping","accessor":"wa","ttl":300,"creation_time":"2024-05-06T07:08:09.123456789Z",
                          "creation_path":"secret/data/foo","wrapped_accessor":""}}
            """);
        t.Vault.Then(HttpStatusCode.OK, """{"data":{"test_string":"unwrapped","test_bool":true}}""");

        var wrapped = await t.Client.ReadAsync("secret/data/foo", new VaultRequestOptions { ResponseWrappingTtl = TimeSpan.FromMinutes(5) });
        var info = wrapped!.WrapInfo!;
        var unwrapped = await t.Client.UnwrapAsync<TestStruct>(info.Token!);

        Assert.Equal(("wa", 300L, "secret/data/foo"), (info.Accessor, info.Ttl, info.CreationPath));
        Assert.Equal(new DateTimeOffset(2024, 5, 6, 7, 8, 9, TimeSpan.Zero).AddTicks(1234567), info.CreationTime);
        Assert.Equal("unwrapped", unwrapped!.Data!.TestString);
        var unwrap = t.Vault.Requests.Last();
        Assert.Equal(HttpMethod.Put, unwrap.Method);
        Assert.Equal("/v1/sys/wrapping/unwrap", unwrap.PathAndQuery);
        Assert.Equal("hvs.wrapping", unwrap.Header("X-Vault-Token"));
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError, """{"errors":["error1", "error2"]}""", new[] { "error1", "error2" }, null, "500 Internal Server Error: error1, error2")]
    [InlineData(HttpStatusCode.Gone, """{"error":"single error"}""", new[] { "single error" }, null, "410 Gone: single error")]
    [InlineData(HttpStatusCode.NotFound, """{"data":{"key1":"value1"}}""", new string[0], """{"data":{"key1":"value1"}}""", """404 Not Found: {"data":{"key1":"value1"}}""")]
    [InlineData(HttpStatusCode.NotFound, """{"errors":[]}""", new string[0], """{"errors":[]}""", """404 Not Found: {"errors":[]}""")]
    [InlineData(HttpStatusCode.BadRequest, """{"errors":[1, "x"]}""", new string[0], """{"errors":[1, "x"]}""", """400 Bad Request: {"errors":[1, "x"]}""")]
    [InlineData((HttpStatusCode)418, "this is just a string", new string[0], "this is just a string", "418 I'm a teapot: this is just a string")]
    [InlineData(HttpStatusCode.Forbidden, "", new string[0], null, "403 Forbidden")]
    [InlineData(HttpStatusCode.BadRequest, """{"error":5}""", new string[0], """{"error":5}""", """400 Bad Request: {"error":5}""")]
    [InlineData(HttpStatusCode.BadRequest, """{"errors":"one"}""", new string[0], """{"errors":"one"}""", """400 Bad Request: {"errors":"one"}""")]
    [InlineData(HttpStatusCode.BadRequest, """{"other":[1],"error":""}""", new string[0], """{"other":[1],"error":""}""", """400 Bad Request: {"other":[1],"error":""}""")]
    [InlineData(HttpStatusCode.BadRequest, """["x"]""", new string[0], """["x"]""", """400 Bad Request: ["x"]""")]
    [InlineData((HttpStatusCode)199, "", new string[0], null, "199 199")]
    public async Task VaultsRefusals_FailWithItsErrors_OrItsBody(HttpStatusCode status, string body, string[] errors, string? raw, string message)
    {
        // Every attempt refused alike: a 500 is retried.
        using var t = await TestClient.CreateAsync();
        t.Vault.Respond = _ => new HttpResponseMessage(status) { Content = new StringContent(body), ReasonPhrase = ReasonPhrase(status) };

        var e = await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("foo"));

        Assert.Equal(status, e.StatusCode);
        Assert.Equal(errors, e.Errors);
        Assert.Equal(raw, e.RawResponseBytes is null ? null : Encoding.UTF8.GetString(e.RawResponseBytes));
        Assert.Equal(message, e.Message);
        Assert.Equal(HttpMethod.Get, e.RequestMethod);
        Assert.Equal("https://vault.test:8200/v1/foo", e.RequestUri.ToString());
        Assert.True(VaultClient.IsErrorStatus(e, status));
        Assert.True(VaultClient.IsErrorStatus(new InvalidOperationException("wrapped", e), status));
        Assert.False(VaultClient.IsErrorStatus(e, HttpStatusCode.OK));
    }

    [Fact]
    public void IsErrorStatus_IsFalseForOtherExceptions()
    {
        Assert.False(VaultClient.IsErrorStatus(null, HttpStatusCode.NotFound));
        Assert.False(VaultClient.IsErrorStatus(new HttpRequestException("x", null, HttpStatusCode.NotFound), HttpStatusCode.NotFound));
    }

    [Fact]
    public async Task AReasonlessRefusal_IsNamedByItsStatus()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(_ => new HttpResponseMessage(HttpStatusCode.Forbidden) { ReasonPhrase = null });

        var e = await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("foo"));

        Assert.Equal("403 Forbidden", e.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData((HttpStatusCode)472)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task SysHealth_IsNeverAnError_ItsStatusIsTheHealth(HttpStatusCode status)
    {
        using var t = await TestClient.CreateAsync(o => o.Retry.RetryMax = 0);
        t.Vault.Then(status, """{"initialized":true,"sealed":true,"standby":false}""");

        var health = await t.Client.System.ReadHealthStatusAsync();

        Assert.True(health!.Data!["sealed"].GetBoolean());
        Assert.Equal("/v1/sys/health", t.Vault.Single().PathAndQuery);
    }

    [Fact]
    public async Task A304_IsNotAnError()
    {
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(HttpStatusCode.NotModified);

        Assert.Null(await t.Client.ReadAsync("a"));
    }

    [Fact]
    public async Task ReadRawAsync_ReturnsTheResponseUnchecked()
    {
        using var t = await TestClient.CreateAsync(o => o.RequestTimeout = TimeSpan.FromMilliseconds(1));
        t.Vault.Delay = TimeSpan.FromMilliseconds(50);
        t.Vault.Then(HttpStatusCode.NotFound, "not json");

        using var response = await t.Client.ReadRawAsync("a", new VaultRequestOptions { QueryParameters = [new("q", "1")] });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("not json", await response.Content.ReadAsStringAsync());
        Assert.Equal("/v1/a?q=1", t.Vault.Single().PathAndQuery);
    }

    [Fact]
    public async Task Callbacks_ClientsRunBeforeRequests()
    {
        var calls = new List<string>();
        using var t = await TestClient.CreateAsync();
        t.Client.SetRequestCallbacks(_ => calls.Add("client request"));
        t.Client.SetResponseCallbacks((_, r) => calls.Add($"client response {(int)r.StatusCode}"));

        await t.Client.ReadAsync("a", new VaultRequestOptions
        {
            RequestCallbacks = [r => r.Headers.Add("x-added", "yes")],
            ResponseCallbacks = [(_, _) => calls.Add("request response")],
        });
        t.Client.ClearRequestCallbacks();
        t.Client.ClearResponseCallbacks();
        await t.Client.ReadAsync("b");

        Assert.Equal(["client request", "client response 200", "request response"], calls);
        Assert.Equal("yes", t.Vault.Requests.First().Header("x-added"));
    }

    [Fact]
    public async Task AThrowingResponseCallback_FailsTheRequest()
    {
        using var t = await TestClient.CreateAsync();

        await Assert.ThrowsAsync<InvalidTimeZoneException>(() => t.Client.ReadAsync("a", new VaultRequestOptions
        {
            ResponseCallbacks = [(_, _) => throw new InvalidTimeZoneException()],
        }));
    }

    [Fact]
    public async Task Clone_CopiesSettings_WhichThenChangeIndependently_AndSharesConnections()
    {
        using var t = await TestClient.CreateAsync(o =>
        {
            o.RequestTimeout = TimeSpan.FromSeconds(30);
            o.Retry.RetryWaitMin = TimeSpan.FromMilliseconds(200);
        });
        t.Client.SetNamespace("test-namespace");
        var clone = t.Client.Clone();
        clone.SetNamespace("clone-namespace");

        await t.Client.ReadAsync("a");
        await clone.ReadAsync("b");
        clone.Dispose();
        await t.Client.ReadAsync("c");

        Assert.Equal(["test-namespace", "clone-namespace", "test-namespace"], t.Vault.Requests.Select(r => r.Header("X-Vault-Namespace")));
        Assert.Equal(FakeVault.Token, t.Vault.Requests.ToArray()[1].Header("X-Vault-Token"));
        Assert.Equal(TimeSpan.FromSeconds(30), clone.Options.RequestTimeout);
        Assert.Equal(TimeSpan.FromMilliseconds(200), clone.Options.Retry.RetryWaitMin);
        Assert.Equal(FakeVault.Address, clone.Options.Address);
    }

    [Fact]
    public async Task Options_IsACopy()
    {
        using var t = await TestClient.CreateAsync();

        t.Client.Options.Tls.InsecureSkipVerify = true;
        t.Client.Options.Retry.RetryMax = 99;

        Assert.False(t.Client.Options.Tls.InsecureSkipVerify);
        Assert.Equal(2, t.Client.Options.Retry.RetryMax);
    }

    [Fact]
    public async Task OptionsChangedAfterwards_ChangeNothing()
    {
        var options = new VaultClientOptions();
        using var t = await TestClient.CreateAsync(o => options = o);

        options.Namespace = "late";
        options.Address = new Uri("https://elsewhere.test");
        await t.Client.ReadAsync("a");

        var request = t.Vault.Single();
        Assert.Null(request.Header("X-Vault-Namespace"));
        Assert.Equal("vault.test", request.Uri.Host);
    }

    [Fact]
    public void UserAgent_NamesTheLibraryAndPlatform_InPrintableAscii()
    {
        Assert.Equal("HkdfGuard.Integration.HashiCorpVault/1.2.3 (Linux #1 ; X64; .NET 10.0.0)",
            VaultUserAgent.Create("1.2.3+abcdef", "Linux #1\n", "X64", "10.0.0"));
        Assert.StartsWith("HkdfGuard.Integration.HashiCorpVault/0.0.0 (", VaultUserAgent.Create(null, "os", "arch", "rt"));

        // An assembly without an informational version: no attributes at all.
        var bare = System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly(new System.Reflection.AssemblyName("bare"),
            System.Reflection.Emit.AssemblyBuilderAccess.Run);
        Assert.StartsWith("HkdfGuard.Integration.HashiCorpVault/0.0.0 (", VaultUserAgent.Create(bare));
        Assert.Equal(VaultUserAgent.Create(typeof(VaultClient).Assembly), VaultUserAgent.Value);
    }

    private static string? ReasonPhrase(HttpStatusCode status) => (int)status switch
    {
        500 => "Internal Server Error",
        410 => "Gone",
        404 => "Not Found",
        400 => "Bad Request",
        418 => "I'm a teapot",
        403 => "Forbidden",
        _ => null,
    };

    internal sealed class TestStruct
    {
        [System.Text.Json.Serialization.JsonPropertyName("test_string")]
        public string? TestString { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("test_bool")]
        public bool TestBool { get; set; }
    }

    private sealed class EmptyTokenProvider : IVaultTokenProvider
    {
        public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => ValueTask.FromResult("");
    }

    private sealed class NonSeekableStream(byte[] content) : MemoryStream(content)
    {
        public override bool CanSeek => false;
    }
}
