using Amazon.Runtime;
using Amazon.Runtime.EventStreams;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

namespace HkdfGuard.Cache.AwsSecretsManager;

/// <summary>A GetSecretValue request whose secret is handed to <see cref="Value"/> instead of the response.</summary>
internal sealed class CapturingGetSecretValueRequest(SecretValueSink value) : GetSecretValueRequest
{
    public SecretValueSink Value { get; } = value;
}

/// <summary>
/// A Secrets Manager client whose pipeline runs <see cref="SecretCaptureHandler"/> between the HTTP
/// call and unmarshalling, so a <see cref="CapturingGetSecretValueRequest"/>'s secret never becomes
/// the response's SecretString or SecretBinary.
/// </summary>
internal sealed class CapturingSecretsManagerClient : AmazonSecretsManagerClient
{
    public CapturingSecretsManagerClient(AmazonSecretsManagerConfig config)
        : base(config)
    {
    }

    public CapturingSecretsManagerClient(AWSCredentials credentials, AmazonSecretsManagerConfig config)
        : base(credentials, config)
    {
    }

    protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
    {
        base.CustomizeRuntimePipeline(pipeline);
        pipeline.AddHandlerAfter<Unmarshaller>(new SecretCaptureHandler());
    }
}

/// <summary>
/// Inside the unmarshaller, so it sees a successful response before it's parsed: for a
/// <see cref="CapturingGetSecretValueRequest"/>, reads the body off the network into
/// <see cref="SecretJsonBody"/>'s pinned memory, hands SecretString or SecretBinary to the request's
/// sink, and gives the unmarshaller the body with both blanked. Every other response passes through.
/// </summary>
internal sealed class SecretCaptureHandler : PipelineHandler
{
    public override async Task<T> InvokeAsync<T>(IExecutionContext executionContext)
    {
        var result = await base.InvokeAsync<T>(executionContext).ConfigureAwait(false);

        if (executionContext.RequestContext.OriginalRequest is CapturingGetSecretValueRequest request
            && executionContext.ResponseContext.HttpResponse is { IsSuccessStatusCode: true } response)
        {
            byte[] redacted;
            using (var body = await response.ResponseBody.OpenResponseAsync().ConfigureAwait(false))
                redacted = await SecretJsonBody.CaptureAsync(body, request.Value, "SecretString", "SecretBinary",
                    executionContext.RequestContext.CancellationToken).ConfigureAwait(false);

            executionContext.ResponseContext.HttpResponse = new RedactedResponse(response, redacted);
        }

        return result;
    }
}

/// <summary>The original response with its body replaced; disposing it disposes the original's.</summary>
internal sealed class RedactedResponse(IWebResponseData inner, byte[] body) : IWebResponseData, IHttpResponseBody
{
    public long ContentLength => body.Length;
    public string ContentType => inner.ContentType;
    public System.Net.HttpStatusCode StatusCode => inner.StatusCode;
    public bool IsSuccessStatusCode => inner.IsSuccessStatusCode;
    public IHttpResponseBody ResponseBody => this;
    public string[] GetHeaderNames() => inner.GetHeaderNames();
    public bool IsHeaderPresent(string headerName) => inner.IsHeaderPresent(headerName);
    public string GetHeaderValue(string headerName) => inner.GetHeaderValue(headerName);
    public IEventStreamHeader GetEventStreamHeader(string headerName) => inner.GetEventStreamHeader(headerName);
    public bool IsEventHeaderPresent(string headerName) => inner.IsEventHeaderPresent(headerName);
    public Stream OpenResponse() => new MemoryStream(body, writable: false);
    public Task<Stream> OpenResponseAsync() => Task.FromResult(OpenResponse());
    public void Dispose() => inner.ResponseBody.Dispose();
}
