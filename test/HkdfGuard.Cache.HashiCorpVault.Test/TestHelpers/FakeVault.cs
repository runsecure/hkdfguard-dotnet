using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.HashiCorpVault.Test.TestHelpers;

/// <summary>
/// A KV secrets engine behind Vault's HTTP API, under the cache's real HttpClient: a GET of a
/// secret's read path with the expected token is answered as Vault answers it - the secret, or 404
/// with an empty error list - for KV version 2 (the default) or 1. A request without that token is
/// refused with 403, as Vault refuses it. Any other request - a LIST, a query, another path - is
/// recorded in <see cref="UnexpectedRequests"/> and refused. Paths are matched exactly, as Vault
/// matches them.
/// </summary>
internal sealed class FakeVault : HttpMessageHandler
{
    public const string Token = "hvs.CAESIFakeTokenForTests";

    public static readonly Uri Address = new("https://vault.test:8200");

    private readonly ConcurrentDictionary<string, Dictionary<string, object?>> _secrets = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _deleted = new(StringComparer.Ordinal);

    /// <summary>Where the engine is mounted, as the cache's options say.</summary>
    public string MountPath { get; init; } = "secret";

    public VaultKvVersion KvVersion { get; init; } = VaultKvVersion.V2;

    /// <summary>The path /v1/ is under, for an address with a path prefix.</summary>
    public string PathPrefix { get; init; } = "";

    /// <summary>Every secret path read, in order.</summary>
    public ConcurrentQueue<string> Reads { get; } = new();

    /// <summary>Every token a read was made with, in order: copies, taken as each request arrived.</summary>
    public ConcurrentQueue<string> Tokens { get; } = new();

    /// <summary>The X-Vault-Token header string of every read itself, to check what became of it.</summary>
    public ConcurrentQueue<string> TokenHeaders { get; } = new();

    /// <summary>The X-Vault-Namespace header of every read, or null where it had none.</summary>
    public ConcurrentQueue<string?> Namespaces { get; } = new();

    /// <summary>Every other request, as "METHOD path?query".</summary>
    public ConcurrentQueue<string> UnexpectedRequests { get; } = new();

    /// <summary>Whether HttpClient ever buffered a response body rather than handing it over as a stream.</summary>
    public bool AnyResponseBuffered { get; private set; }

    /// <summary>When set, a read is answered with this status and body as they are.</summary>
    public (HttpStatusCode Status, string Body)? Answer { get; set; }

    /// <summary>Runs inside every read before it answers, e.g. to hold it open.</summary>
    public Action? OnRead { get; set; }

    public void SetData(string path, Dictionary<string, object?> data) => _secrets[path] = data;

    public void Set(string path, string value) => SetData(path, new Dictionary<string, object?> { ["value"] = value });

    /// <summary>A KV version 2 secret whose latest version is deleted: Vault answers 404 with its metadata.</summary>
    public void SetDeleted(string path) => _deleted[path] = true;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var readPrefix = $"{PathPrefix}/v1/{MountPath}/" + (KvVersion == VaultKvVersion.V2 ? "data/" : "");
        var uri = request.RequestUri!;
        if (request.Method != HttpMethod.Get || uri.Query.Length > 0 || !uri.AbsolutePath.StartsWith(readPrefix, StringComparison.Ordinal)
            || $"{uri.Scheme}://{uri.Authority}" != $"{Address.Scheme}://{Address.Authority}")
        {
            UnexpectedRequests.Enqueue($"{request.Method} {uri.PathAndQuery}");
            return Respond(HttpStatusCode.MethodNotAllowed, """{"errors":["1 error occurred:\n\t* unsupported operation\n\n"]}""");
        }

        Assert.Equal("true", Assert.Single(request.Headers.GetValues("X-Vault-Request")));
        var header = request.Headers.TryGetValues("X-Vault-Token", out var tokens) ? Assert.Single(tokens) : "";
        TokenHeaders.Enqueue(header);
        var token = new string(header.AsSpan());
        Namespaces.Enqueue(request.Headers.TryGetValues("X-Vault-Namespace", out var namespaces) ? Assert.Single(namespaces) : null);
        Tokens.Enqueue(token);

        var path = uri.AbsolutePath[readPrefix.Length..];
        Reads.Enqueue(path);
        OnRead?.Invoke();

        if (token != Token)
            return Respond(HttpStatusCode.Forbidden, """{"errors":["permission denied"]}""");
        if (Answer is { } answer)
            return Respond(answer.Status, answer.Body);
        if (_deleted.ContainsKey(path))
            return Respond(HttpStatusCode.NotFound, Envelope(new { data = (object?)null, metadata = Metadata(deleted: true) }));
        if (!_secrets.TryGetValue(path, out var data))
            return Respond(HttpStatusCode.NotFound, """{"errors":[]}""");

        return Respond(HttpStatusCode.OK, KvVersion == VaultKvVersion.V2
            ? Envelope(new { data, metadata = Metadata(deleted: false) })
            : Envelope(data, leaseDuration: 2764800));
    }

    private static object Metadata(bool deleted) => new
    {
        created_time = "2026-10-28T12:00:00.000000Z",
        custom_metadata = (object?)null,
        deletion_time = deleted ? "2026-10-28T13:00:00.000000Z" : "",
        destroyed = false,
        version = 3,
    };

    private static string Envelope(object data, int leaseDuration = 0) => JsonSerializer.Serialize(new
    {
        request_id = "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a",
        lease_id = "",
        renewable = false,
        lease_duration = leaseDuration,
        data,
        wrap_info = (object?)null,
        warnings = (object?)null,
        auth = (object?)null,
        mount_type = "kv",
    });

    private Task<HttpResponseMessage> Respond(HttpStatusCode status, string body)
        => Task.FromResult(new HttpResponseMessage(status) { Content = new TrackingContent(this, Encoding.UTF8.GetBytes(body)) });

    // A body that notices being buffered: HttpClient buffers through SerializeToStreamAsync, and
    // hands an unbuffered body over through CreateContentReadStreamAsync.
    private sealed class TrackingContent : HttpContent
    {
        private readonly FakeVault _owner;
        private readonly byte[] _body;

        public TrackingContent(FakeVault owner, byte[] body)
        {
            _owner = owner;
            _body = body;
            Headers.ContentType = new("application/json");
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            _owner.AnyResponseBuffered = true;
            return stream.WriteAsync(_body).AsTask();
        }

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new MemoryStream(_body, writable: false));

        protected override bool TryComputeLength(out long length)
        {
            length = _body.Length;
            return true;
        }
    }
}

/// <summary>
/// A token provider that counts its calls, and can hand out any token or fail. Each token Next
/// gives is protected by <see cref="Protector"/>, as a real provider's is, unless
/// <see cref="Unprotected"/>.
/// </summary>
internal sealed class FakeTokenProvider : IVaultTokenProvider
{
    private int _calls;

    public int Calls => _calls;

    public Func<int, CancellationToken, ValueTask<string>> Next { get; set; } = (_, _) => ValueTask.FromResult(FakeVault.Token);

    /// <summary>Protects every token handed out; the tests set it to the cache's own token protector.</summary>
    public IDataProtector? Protector { get; set; }

    /// <summary>Hands tokens out exactly as Next gives them, as a provider that doesn't protect them would.</summary>
    public bool Unprotected { get; init; }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        var token = await Next(Interlocked.Increment(ref _calls), cancellationToken);
        return Unprotected || Protector is null ? token : Protector.Encrypt(token);
    }
}
