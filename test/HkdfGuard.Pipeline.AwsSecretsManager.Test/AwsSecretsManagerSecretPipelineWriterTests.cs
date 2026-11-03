using System.Collections.Concurrent;
using System.Net;
using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.Internal.Transform;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;
using HkdfGuard.Pipeline.AwsSecretsManager.Test.TestHelpers;
using HkdfGuard.Pipeline.Test.TestHelpers;

namespace HkdfGuard.Pipeline.AwsSecretsManager.Test;

/// <summary>The writer's contract, and what only it does, with its real client and capture handler against a fake endpoint.</summary>
public sealed class AwsSecretsManagerSecretPipelineWriterTests : SecretPipelineWriterContractTests
{
    private readonly FakeSecretsManager _aws = new();

    // No key ring anywhere: the only key is the protector's.
    protected override ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames)
        => Create(protector, secretNames);

    protected override void SetText(string name, string text) => _aws.SetString(name, text);

    protected override void SetKeys(string name, string json) => _aws.SetString(name, json);

    protected override void FailReads() => _aws.FailWith = ("AccessDeniedException", HttpStatusCode.BadRequest);

    protected override Type ReadFailure => typeof(AmazonSecretsManagerException);

    protected override IEnumerable<string> Reads => _aws.Gets;

    private AwsSecretsManagerSecretPipelineWriter Create(IPipelineDataProtector protector, IList<string> secretNames)
        => new(protector, secretNames, _aws.Config(), FakeSecretsManager.Credentials);

    // What every response the client's unmarshaller produced held, read as it was produced.
    private static ConcurrentQueue<(string? Arn, string? SecretString, long? SecretBinaryLength)> Unmarshalled(AwsSecretsManagerSecretPipelineWriter writer)
    {
        var responses = new ConcurrentQueue<(string?, string?, long?)>();
        writer.Client.AfterResponseEvent += (_, e) =>
        {
            var response = (GetSecretValueResponse)((WebServiceResponseEventArgs)e).Response;
            responses.Enqueue((response.ARN, response.SecretString, response.SecretBinary?.Length));
        };
        return responses;
    }

    [Fact]
    public async Task TheUnmarshalledResponse_HoldsNothing()
    {
        _aws.SetString("item", "s3cret");
        using var writer = Create(Protector, ["item"]);
        var responses = Unmarshalled(writer);

        await writer.PullSecretsAsync();

        Assert.Equal((null, null, null), Assert.Single(responses));
        Assert.Empty(_aws.UnexpectedOperations);
    }

    [Fact]
    public async Task AnotherRequestOnTheWritersClient_PassesThroughUntouched()
    {
        _aws.SetString("item", "s3cret");
        using var writer = Create(Protector, ["item"]);

        var response = await writer.Client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = "item" });

        Assert.Equal("s3cret", response.SecretString);
    }

    [Fact]
    public async Task ANameWithoutAKey_ReadsTheWholeSecretString()
    {
        _aws.SetString("prod/app", """{"user":"app"}""");
        using var writer = Create(Protector, ["prod/app", "prod/app#user"]);

        await writer.PullSecretsAsync();

        Assert.Equal("""{"user":"app"}""", Decrypt(writer.ProtectedSecrets["prod__app"], "prod__app"));
        Assert.Equal("app", Decrypt(writer.ProtectedSecrets["prod__app__user"], "prod__app__user"));
        Assert.Equal(["prod/app"], _aws.Gets);
    }

    [Fact]
    public async Task AnEmptySecret_IsMissing()
    {
        _aws.SetEmpty("empty");
        using var writer = Create(Protector, ["empty"]);

        await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());
    }

    [Fact]
    public async Task ASecretBinary_IsRefused()
    {
        _aws.SetBinary("binary", [1, 2, 3]);
        using var writer = Create(Protector, ["binary"]);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Theory]
    [InlineData("""{"SecretString":"x" """)]
    [InlineData("""["SecretString"]""")]
    [InlineData("")]
    public async Task AResponseThatIsntSecretsManagersJson_IsRefused(string body)
    {
        _aws.RawBody = body;
        using var writer = Create(Protector, ["item"]);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Theory]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("user@example")]
    [InlineData("a+b")]
    [InlineData("a=b")]
    [InlineData(".hidden")]
    public void ANameNoFileCanHave_IsRefused(string secretName)
        => Assert.Throws<ArgumentException>(() => Create(Protector, [secretName]));

    [Fact]
    public void IsValidSecretName_IsSecretsManagersRule()
    {
        Assert.True(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName("prod/a_b+c=d.e@f-g"));
        Assert.True(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName(new string('a', AwsSecretsManagerSecretPipelineWriter.MaxSecretNameLength)));
        Assert.False(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName(new string('a', AwsSecretsManagerSecretPipelineWriter.MaxSecretNameLength + 1)));
        Assert.False(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName(""));
        Assert.False(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName(null));
        Assert.False(AwsSecretsManagerSecretPipelineWriter.IsValidSecretName("a:b"));
    }

    [Fact]
    public void WithoutCredentials_TheSdksDefaultChainIsUsed()
    {
        // Credentials are resolved when a request is signed, not when the client is made.
        using var withConfig = new AwsSecretsManagerSecretPipelineWriter(Protector, ["item"], _aws.Config());
        using var withNothing = new AwsSecretsManagerSecretPipelineWriter(Protector, ["item"], new AmazonSecretsManagerConfig { RegionEndpoint = RegionEndpoint.USEast1 });
        using var defaults = new AwsSecretsManagerSecretPipelineWriter(Protector, ["item"]);
    }

    [Fact]
    public void ARedactedResponse_IsTheOriginalWithItsBodyReplaced()
    {
        var inner = new FakeResponse();
        var redacted = new RedactedResponse(inner, "{}"u8.ToArray());

        Assert.Equal(2, redacted.ContentLength);
        Assert.Equal("application/x-amz-json-1.1", redacted.ContentType);
        Assert.Equal(HttpStatusCode.OK, redacted.StatusCode);
        Assert.True(redacted.IsSuccessStatusCode);
        Assert.Same(redacted, redacted.ResponseBody);
        Assert.Equal(["x-amzn-RequestId"], redacted.GetHeaderNames());
        Assert.True(redacted.IsHeaderPresent("x-amzn-RequestId"));
        Assert.Equal("request-id", redacted.GetHeaderValue("x-amzn-RequestId"));
        Assert.Null(redacted.GetEventStreamHeader("x"));
        Assert.False(redacted.IsEventHeaderPresent("x"));
        Assert.Equal("{}"u8.ToArray(), ((MemoryStream)redacted.OpenResponse()).ToArray());

        redacted.Dispose();
        Assert.True(inner.Disposed);
    }

    private sealed class FakeResponse : IWebResponseData, IHttpResponseBody
    {
        public bool Disposed { get; private set; }
        public long ContentLength => 0;
        public string ContentType => "application/x-amz-json-1.1";
        public HttpStatusCode StatusCode => HttpStatusCode.OK;
        public bool IsSuccessStatusCode => true;
        public IHttpResponseBody ResponseBody => this;
        public string[] GetHeaderNames() => ["x-amzn-RequestId"];
        public bool IsHeaderPresent(string headerName) => headerName == "x-amzn-RequestId";
        public string GetHeaderValue(string headerName) => "request-id";
        public Amazon.Runtime.EventStreams.IEventStreamHeader GetEventStreamHeader(string headerName) => null!;
        public bool IsEventHeaderPresent(string headerName) => false;
        public Stream OpenResponse() => Stream.Null;
        public Task<Stream> OpenResponseAsync() => Task.FromResult(Stream.Null);
        public void Dispose() => Disposed = true;
    }
}
