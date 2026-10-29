using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;

namespace HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;

/// <summary>
/// Key Vault's secrets endpoint over HTTP, behind a real SecretClient: a request without a bearer
/// token gets Key Vault's 401 challenge, and an authorized Get Secret is answered with the secret's
/// JSON (names compared ignoring case, as Key Vault does) or a 404. Any request other than Get Secret
/// - listing secrets or versions among them - is recorded in <see cref="UnexpectedRequests"/> and
/// refused. <see cref="Options"/> also installs a policy recording every body SecretClient was given
/// to deserialize, so a test can check the secret never reached it.
/// </summary>
internal sealed class FakeKeyVault : HttpMessageHandler
{
    public static readonly Uri VaultUri = new("https://hkdfguard-test.vault.azure.net/");

    private readonly ConcurrentDictionary<string, string> _secrets = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The name of every authorized Get Secret, in order.</summary>
    public ConcurrentQueue<string> Gets { get; } = new();

    /// <summary>Every other request, as "METHOD path".</summary>
    public ConcurrentQueue<string> UnexpectedRequests { get; } = new();

    /// <summary>Every response body SecretClient deserialized.</summary>
    public ConcurrentQueue<string> BodiesSeenBySecretClient { get; } = new();

    /// <summary>When set, an authorized Get Secret is answered with this status and an error body.</summary>
    public HttpStatusCode? FailWith { get; set; }

    /// <summary>When set, an authorized Get Secret is answered with this body as it is.</summary>
    public string? RawBody { get; set; }

    /// <summary>Runs inside every authorized Get Secret before it answers, e.g. to hold it open.</summary>
    public Action? OnGet { get; set; }

    public void Set(string name, string value) => _secrets[name] = value;

    /// <summary>Client options sending every request here, without retries.</summary>
    public SecretClientOptions Options()
    {
        var options = new SecretClientOptions { Transport = new HttpClientTransport(new HttpClient(this)) };
        options.Retry.MaxRetries = 0;
        options.AddPolicy(new BodyRecorder(this), HttpPipelinePosition.PerCall);
        return options;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(Send(request, cancellationToken));

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath.Trim('/').Split('/');
        if (request.Method != HttpMethod.Get || path.Length != 2 || path[0] != "secrets")
        {
            UnexpectedRequests.Enqueue($"{request.Method} {request.RequestUri.AbsolutePath}");
            return Json(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden","message":"Not allowed in a test."}}""");
        }

        if (request.Headers.Authorization is null)
        {
            var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("") };
            challenge.Headers.Add("WWW-Authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000\", resource=\"https://vault.azure.net\"");
            return challenge;
        }

        var name = path[1];
        Gets.Enqueue(name);
        OnGet?.Invoke();
        if (FailWith is { } status)
            return Json(status, """{"error":{"code":"Forbidden","message":"Refused in a test."}}""");
        if (RawBody is not null)
            return Json(HttpStatusCode.OK, RawBody);
        if (!_secrets.TryGetValue(name, out var value))
            return Json(HttpStatusCode.NotFound, $$$"""{"error":{"code":"SecretNotFound","message":"A secret with (name/id) {{{name}}} was not found in this key vault."}}""");

        return Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
        {
            value,
            id = $"{VaultUri.AbsoluteUri}secrets/{name}/0123456789abcdef0123456789abcdef",
            attributes = new { enabled = true, created = 1700000000, updated = 1700000000, recoveryLevel = "Recoverable+Purgeable" },
            tags = new { value = "a tag, not the secret" },
        }));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // Outermost, so it sees the response exactly as SecretClient will deserialize it.
    private sealed class BodyRecorder(FakeKeyVault vault) : HttpPipelineSynchronousPolicy
    {
        public override void OnReceivedResponse(HttpMessage message)
        {
            if (message.Response.ContentStream is not MemoryStream body)
                return;

            vault.BodiesSeenBySecretClient.Enqueue(Encoding.UTF8.GetString(body.ToArray()));
        }
    }
}

/// <summary>A credential that always has a token.</summary>
internal sealed class FakeCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new("fake-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}
