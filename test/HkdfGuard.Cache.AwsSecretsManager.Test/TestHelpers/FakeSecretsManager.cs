using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Amazon;
using Amazon.Runtime;
using Amazon.SecretsManager;

namespace HkdfGuard.Cache.AwsSecretsManager.Test.TestHelpers;

/// <summary>
/// Secrets Manager's JSON 1.1 endpoint over HTTP, behind the cache's real client: an authorized
/// GetSecretValue is answered with the secret (names matched exactly, as AWS matches them) or
/// ResourceNotFoundException. Any other operation - ListSecrets and BatchGetSecretValue among them -
/// is recorded in <see cref="UnexpectedOperations"/> and refused.
/// </summary>
internal sealed class FakeSecretsManager : HttpMessageHandler
{
    private readonly ConcurrentDictionary<string, Dictionary<string, object>> _secrets = new(StringComparer.Ordinal);

    /// <summary>Every SecretId GetSecretValue was called with, in order.</summary>
    public ConcurrentQueue<string> Gets { get; } = new();

    /// <summary>Every other operation called.</summary>
    public ConcurrentQueue<string> UnexpectedOperations { get; } = new();

    /// <summary>When set, GetSecretValue fails with this AWS error type and status.</summary>
    public (string Type, HttpStatusCode Status)? FailWith { get; set; }

    /// <summary>When set, GetSecretValue is answered with this body as it is.</summary>
    public string? RawBody { get; set; }

    /// <summary>Runs inside every GetSecretValue before it answers, e.g. to hold it open.</summary>
    public Action? OnGet { get; set; }

    public void SetString(string name, string value) => _secrets[name] = new() { ["SecretString"] = value };

    public void SetBinary(string name, byte[] value) => _secrets[name] = new() { ["SecretBinary"] = Convert.ToBase64String(value) };

    public void SetEmpty(string name) => _secrets[name] = [];

    /// <summary>Client config sending every request here, without retries.</summary>
    public AmazonSecretsManagerConfig Config() => new()
    {
        RegionEndpoint = RegionEndpoint.USEast1,
        HttpClientFactory = new Factory(this),
        MaxErrorRetry = 0,
    };

    public static AWSCredentials Credentials { get; } = new BasicAWSCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var operation = request.Headers.GetValues("X-Amz-Target").Single();
        if (operation != "secretsmanager.GetSecretValue")
        {
            UnexpectedOperations.Enqueue(operation);
            return Error("AccessDeniedException", HttpStatusCode.BadRequest);
        }

        // SigV4: present as a raw header, which HttpRequestHeaders.Authorization doesn't parse.
        Assert.StartsWith("AWS4-HMAC-SHA256 ", Assert.Single(request.Headers.NonValidated["Authorization"]), StringComparison.Ordinal);
        using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var name = body.RootElement.GetProperty("SecretId").GetString()!;
        Assert.False(body.RootElement.TryGetProperty("VersionId", out _));
        Assert.False(body.RootElement.TryGetProperty("VersionStage", out _));

        Gets.Enqueue(name);
        OnGet?.Invoke();
        if (FailWith is { } failure)
            return Error(failure.Type, failure.Status);
        if (RawBody is not null)
            return Json(HttpStatusCode.OK, RawBody);
        if (!_secrets.TryGetValue(name, out var value))
            return Error("ResourceNotFoundException", HttpStatusCode.BadRequest);

        var response = new Dictionary<string, object>(value)
        {
            ["ARN"] = $"arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}-AbCdEf",
            ["Name"] = name,
            ["VersionId"] = "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
            ["VersionStages"] = new[] { "AWSCURRENT" },
            ["CreatedDate"] = 1700000000.0,
        };
        return Json(HttpStatusCode.OK, JsonSerializer.Serialize(response));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/x-amz-json-1.1") };

    private static HttpResponseMessage Error(string type, HttpStatusCode status)
    {
        var response = Json(status, JsonSerializer.Serialize(new Dictionary<string, string> { ["__type"] = type, ["Message"] = $"{type} in a test." }));
        response.Headers.Add("x-amzn-ErrorType", type);
        return response;
    }

    private sealed class Factory(HttpMessageHandler handler) : HttpClientFactory
    {
        public override HttpClient CreateHttpClient(IClientConfig clientConfig) => new(handler, disposeHandler: false);

        public override bool UseSDKHttpClientCaching(IClientConfig clientConfig) => false;
    }
}
