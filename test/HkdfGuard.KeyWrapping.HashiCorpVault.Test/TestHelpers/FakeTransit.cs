using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace HkdfGuard.KeyWrapping.HashiCorpVault.Test.TestHelpers;

/// <summary>
/// A transit secrets engine behind Vault's HTTP API, under the wrapper's real HttpClient. A POST
/// to encrypt, decrypt or datakey/wrapped for a key it holds, with the expected token, is answered
/// as Vault 1.19 answers it: ciphertext is "vault:v1:" and base64 of AES-GCM under that key's own
/// local key, with associated_data as the AAD, so decrypt fails unless the key and the context both
/// match. datakey/wrapped ignores associated_data and says so in its warnings, as Vault does. A
/// request without the token is refused with 403. Any other request is recorded in
/// <see cref="UnexpectedRequests"/> and refused.
/// </summary>
internal sealed class FakeTransit : HttpMessageHandler
{
    public const string Token = "hvs.CAESIFakeTokenForTests";

    public const string KeyName = "myapp-kek";

    public static readonly Uri Address = new("https://vault.test:8200");

    private static readonly FieldInfo MemoryContentField =
        typeof(ReadOnlyMemoryContent).GetField("_content", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("ReadOnlyMemoryContent no longer keeps its memory in _content.");

    private readonly ConcurrentDictionary<string, byte[]> _keys = new(StringComparer.Ordinal);

    public FakeTransit() => AddKey(KeyName);

    /// <summary>Where the engine is mounted, as the wrapper's options say.</summary>
    public string MountPath { get; init; } = "transit";

    /// <summary>The path /v1/ is under, for an address with a path prefix.</summary>
    public string PathPrefix { get; init; } = "";

    /// <summary>Every transit request, in order: its operation, key and body, copied as it arrived.</summary>
    public ConcurrentQueue<TransitRequest> Requests { get; } = new();

    /// <summary>The memory every request body was sent from, to check what became of it.</summary>
    public ConcurrentQueue<ReadOnlyMemory<byte>> BodyMemory { get; } = new();

    /// <summary>The X-Vault-Token header string of every request itself, to check what became of it.</summary>
    public ConcurrentQueue<string> TokenHeaders { get; } = new();

    /// <summary>Every other request, as "METHOD path?query".</summary>
    public ConcurrentQueue<string> UnexpectedRequests { get; } = new();

    /// <summary>Whether HttpClient ever buffered a response body rather than handing it over as a stream.</summary>
    public bool AnyResponseBuffered { get; private set; }

    /// <summary>
    /// When set, answers a request in place of the engine: its status and body as they are, or null
    /// to let the engine answer. Given the request and how many have arrived, this one included.
    /// </summary>
    public Func<TransitRequest, int, (HttpStatusCode Status, string Body)?>? Answer { get; set; }

    /// <summary>Runs inside every request before it answers, e.g. to hold it open.</summary>
    public Func<CancellationToken, Task>? OnRequest { get; set; }

    /// <summary>Answers as a Vault too old for associated_data would: ignoring it, with a warning.</summary>
    public bool IgnoresAssociatedData { get; set; }

    public void AddKey(string name) => _keys[name] = RandomNumberGenerator.GetBytes(32);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var prefix = $"{PathPrefix}/v1/{MountPath}/";
        var route = uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal) ? uri.AbsolutePath[prefix.Length..] : "";
        var (operation, key) = route switch
        {
            _ when route.StartsWith("encrypt/", StringComparison.Ordinal) => ("encrypt", route["encrypt/".Length..]),
            _ when route.StartsWith("decrypt/", StringComparison.Ordinal) => ("decrypt", route["decrypt/".Length..]),
            _ when route.StartsWith("datakey/wrapped/", StringComparison.Ordinal) => ("datakey", route["datakey/wrapped/".Length..]),
            _ => ("", ""),
        };
        if (request.Method != HttpMethod.Post || operation.Length == 0 || key.Contains('/') || uri.Query.Length > 0
            || $"{uri.Scheme}://{uri.Authority}" != $"{Address.Scheme}://{Address.Authority}")
        {
            UnexpectedRequests.Enqueue($"{request.Method} {uri.PathAndQuery}");
            return Respond(HttpStatusCode.MethodNotAllowed, """{"errors":["1 error occurred:\n\t* unsupported operation\n\n"]}""");
        }

        Assert.Equal("true", Assert.Single(request.Headers.GetValues("X-Vault-Request")));
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        var header = request.Headers.TryGetValues("X-Vault-Token", out var tokens) ? Assert.Single(tokens) : "";
        TokenHeaders.Enqueue(header);
        if (request.Content is ReadOnlyMemoryContent memoryContent)
            BodyMemory.Enqueue((ReadOnlyMemory<byte>)MemoryContentField.GetValue(memoryContent)!);

        var body = await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var recorded = new TransitRequest(operation, key, body, new string(header.AsSpan()),
            request.Headers.TryGetValues("X-Vault-Namespace", out var namespaces) ? Assert.Single(namespaces) : null);
        Requests.Enqueue(recorded);

        if (OnRequest is not null)
            await OnRequest(cancellationToken);

        if (recorded.Token != Token)
            return Respond(HttpStatusCode.Forbidden, """{"errors":["1 error occurred:\n\t* permission denied\n\n"]}""");
        if (Answer?.Invoke(recorded, Requests.Count) is { } answer)
            return Respond(answer.Status, answer.Body);
        if (!_keys.TryGetValue(key, out var keyBytes))
            return Respond(HttpStatusCode.BadRequest, """{"errors":["encryption key not found"]}""");

        var json = JsonNode.Parse(body)!.AsObject();
        var ignored = new List<string>();
        foreach (var (name, _) in json)
        {
            var known = operation switch
            {
                "encrypt" => name is "plaintext" || (name is "associated_data" && !IgnoresAssociatedData),
                "decrypt" => name is "ciphertext" || (name is "associated_data" && !IgnoresAssociatedData),
                _ => name is "bits",
            };
            if (!known)
                ignored.Add(name);
        }

        var aad = ignored.Contains("associated_data") || json["associated_data"] is null
            ? []
            : Convert.FromBase64String(json["associated_data"]!.GetValue<string>());
        var warnings = ignored.Count > 0 ? new[] { $"Endpoint ignored these unrecognized parameters: [{string.Join(" ", ignored)}]" } : null;

        switch (operation)
        {
            case "encrypt":
                return Respond(HttpStatusCode.OK, Envelope(new { ciphertext = Seal(keyBytes, Convert.FromBase64String(json["plaintext"]!.GetValue<string>()), aad), key_version = 1 }, warnings));

            case "datakey":
                return Respond(HttpStatusCode.OK, Envelope(new { ciphertext = Seal(keyBytes, RandomNumberGenerator.GetBytes(json["bits"]!.GetValue<int>() / 8), aad), key_version = 1 }, warnings));

            default:
                var ciphertext = json["ciphertext"]!.GetValue<string>();
                if (!ciphertext.StartsWith("vault:v1:", StringComparison.Ordinal))
                    return Respond(HttpStatusCode.BadRequest, """{"errors":["invalid ciphertext: no prefix"]}""");
                var plaintext = Open(keyBytes, Convert.FromBase64String(ciphertext["vault:v1:".Length..]), aad);
                return plaintext is null
                    ? Respond(HttpStatusCode.BadRequest, """{"errors":["cipher: message authentication failed"]}""")
                    : Respond(HttpStatusCode.OK, Envelope(new { plaintext = Convert.ToBase64String(plaintext) }, warnings));
        }
    }

    // Escapes as Vault's (Go's) encoder does: leaves '+' alone, unlike System.Text.Json's default.
    private static readonly JsonSerializerOptions GoLike = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>A body shaped as Vault shapes a successful answer.</summary>
    public static string Envelope(object data, string[]? warnings = null) => JsonSerializer.Serialize(new
    {
        request_id = "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a",
        lease_id = "",
        renewable = false,
        lease_duration = 0,
        data,
        wrap_info = (object?)null,
        warnings,
        auth = (object?)null,
        mount_type = "transit",
    }, GoLike);

    private static string Seal(byte[] key, byte[] plaintext, byte[] aad)
    {
        var sealedBlob = new byte[12 + plaintext.Length + 16];
        RandomNumberGenerator.Fill(sealedBlob.AsSpan(0, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(sealedBlob.AsSpan(0, 12), plaintext, sealedBlob.AsSpan(12, plaintext.Length), sealedBlob.AsSpan(12 + plaintext.Length), aad);
        return "vault:v1:" + Convert.ToBase64String(sealedBlob);
    }

    private static byte[]? Open(byte[] key, byte[] sealedBlob, byte[] aad)
    {
        if (sealedBlob.Length < 28)
            return null;

        var plaintext = new byte[sealedBlob.Length - 28];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(sealedBlob.AsSpan(0, 12), sealedBlob.AsSpan(12, plaintext.Length), sealedBlob.AsSpan(12 + plaintext.Length), plaintext, aad);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
    }

    private HttpResponseMessage Respond(HttpStatusCode status, string body)
        => new(status) { Content = new TrackingContent(this, Encoding.UTF8.GetBytes(body)) };

    // A body that notices being buffered: HttpClient buffers through SerializeToStreamAsync, and
    // hands an unbuffered body over through CreateContentReadStreamAsync.
    private sealed class TrackingContent : HttpContent
    {
        private readonly FakeTransit _owner;
        private readonly byte[] _body;

        public TrackingContent(FakeTransit owner, byte[] body)
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

/// <summary>One transit request as it arrived: the body and token are copies.</summary>
internal sealed record TransitRequest(string Operation, string Key, byte[] Body, string Token, string? Namespace)
{
    public JsonObject Json => JsonNode.Parse(Body)!.AsObject();

    public string? Field(string name) => Json[name]?.ToString();
}

/// <summary>A token source that counts its calls, and can hand out any token or fail.</summary>
internal sealed class FakeTokenSource : IVaultTokenSource
{
    private int _calls;

    public int Calls => _calls;

    public Func<int, CancellationToken, ValueTask<string>> Next { get; set; } = (_, _) => ValueTask.FromResult(FakeTransit.Token);

    public async ValueTask<int> CopyTokenAsync(Memory<char> destination, CancellationToken cancellationToken)
    {
        var token = await Next(Interlocked.Increment(ref _calls), cancellationToken);
        token.AsSpan(0, Math.Min(token.Length, destination.Length)).CopyTo(destination.Span);
        return token.Length;
    }
}
