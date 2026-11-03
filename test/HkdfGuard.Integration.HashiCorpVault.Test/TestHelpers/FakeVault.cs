using System.Collections.Concurrent;
using System.Net;
using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

/// <summary>
/// Vault's HTTP API as the client's HttpClient sees it: every request is recorded as it arrives -
/// headers and body copied then, since the client zeroes its token once the request is sent - and
/// answered by the next queued responder, or by <see cref="Respond"/> once the queue is empty.
/// </summary>
internal sealed class FakeVault : HttpMessageHandler
{
    public const string Token = "hvs.CAESIFakeTokenForTests";

    public static readonly Uri Address = new("https://vault.test:8200");

    private readonly ConcurrentQueue<Func<Received, HttpResponseMessage>> _queued = new();

    /// <summary>Every request, in order.</summary>
    public ConcurrentQueue<Received> Requests { get; } = new();

    /// <summary>Answers a request once the queue is empty; 200 with {"data":{}} unless set.</summary>
    public Func<Received, HttpResponseMessage> Respond { get; set; } = _ => Json(HttpStatusCode.OK, """{"data":{}}""");

    /// <summary>Makes each request wait this long before it's answered (or cancelled).</summary>
    public TimeSpan Delay { get; set; }

    public Received Single() => Assert.Single(Requests);

    public FakeVault Then(Func<Received, HttpResponseMessage> responder)
    {
        _queued.Enqueue(responder);
        return this;
    }

    public FakeVault Then(HttpStatusCode status, string? json = null, params (string Name, string Value)[] headers)
        => Then(_ => Json(status, json, headers));

    public FakeVault ThenThrow(Exception exception) => Then(_ => throw exception);

    public static HttpResponseMessage Json(HttpStatusCode status, string? json, params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage(status);
        if (json is not null)
            response.Content = new StringContent(json, Encoding.UTF8, "application/json");
        foreach (var (name, value) in headers)
            response.Headers.TryAddWithoutValidation(name, value);
        return response;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        string? tokenHeader = null;
        foreach (var (name, values) in request.Headers.NonValidated)
        {
            // Copies: the client zeroes the token's string once the request has gone.
            headers[name] = values.Select(v => new string(v.AsSpan())).ToArray();
            if (name.Equals("X-Vault-Token", StringComparison.OrdinalIgnoreCase))
                tokenHeader = values.First();
        }

        byte[]? body = null;
        if (request.Content is not null)
        {
            foreach (var (name, values) in request.Content.Headers.NonValidated)
                headers[name] = values.Select(v => new string(v.AsSpan())).ToArray();
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
        }

        var received = new Received(request.Method, request.RequestUri!, headers, body, tokenHeader);
        Requests.Enqueue(received);

        if (Delay > TimeSpan.Zero)
            await Task.Delay(Delay, cancellationToken);

        var response = _queued.TryDequeue(out var next) ? next(received) : Respond(received);
        response.RequestMessage = request;
        return response;
    }

    /// <summary>A request as it arrived.</summary>
    /// <param name="TokenHeader">The X-Vault-Token header string itself, not a copy: to check it's zeroed afterwards.</param>
    public sealed record Received(HttpMethod Method, Uri Uri, Dictionary<string, string[]> Headers, byte[]? Body, string? TokenHeader)
    {
        public string? Header(string name) => Headers.TryGetValue(name, out var values) ? string.Join(",", values) : null;

        public string? BodyText => Body is null ? null : Encoding.UTF8.GetString(Body);

        public string PathAndQuery => Uri.PathAndQuery;
    }
}

/// <summary>A client over a <see cref="FakeVault"/>, its token protector, and the fake token already protected and set.</summary>
internal sealed record TestClient(VaultClient Client, FakeVault Vault, IDataProtector Protector) : IDisposable
{
    public static async Task<TestClient> CreateAsync(Action<VaultClientOptions>? configure = null, FakeVault? vault = null, bool withToken = true)
    {
        vault ??= new FakeVault();
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(VaultClient.TokenPurpose);
        var options = new VaultClientOptions
        {
            Address = FakeVault.Address,
            HttpMessageHandler = vault,
            // No waits between retries: tests that meet a 5xx stay quick.
            Retry = { RetryWaitMin = TimeSpan.Zero, RetryWaitMax = TimeSpan.Zero },
        };
        if (withToken)
            options.Token = StaticVaultToken.Protect(protector, FakeVault.Token);
        configure?.Invoke(options);
        return new TestClient(new VaultClient(protector, options), vault, protector);
    }

    /// <summary>The token protected holds, decrypted with this client's protector.</summary>
    public string Decrypt(StaticVaultToken protectedToken)
    {
        var chars = new char[Protector.GetMaxDecryptedLength(protectedToken.ToString())];
        return new string(chars, 0, Protector.Decrypt(protectedToken.ToString(), chars));
    }

    public void Dispose() => Client.Dispose();
}
