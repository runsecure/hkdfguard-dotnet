using Amazon.Runtime;
using Amazon.Runtime.EventStreams;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Pipeline.AwsSecretsManager;

/// <summary>Takes a successful GetSecretValue response body, in pinned memory zeroed once this returns.</summary>
internal delegate void SecretBodyCapture(ReadOnlySpan<byte> body);

/// <summary>A GetSecretValue request whose response body is handed to <see cref="Capture"/> instead of the response.</summary>
internal sealed class PipelineGetSecretValueRequest(SecretBodyCapture capture) : GetSecretValueRequest
{
    public SecretBodyCapture Capture { get; } = capture;
}

/// <summary>
/// The pipeline writer's Secrets Manager client: its pipeline runs <see cref="PipelineSecretCaptureHandler"/>
/// between the HTTP call and unmarshalling, so a <see cref="PipelineGetSecretValueRequest"/>'s secret
/// never becomes the response's SecretString or SecretBinary.
/// </summary>
internal sealed class PipelineSecretsManagerClient : AmazonSecretsManagerClient
{
    public PipelineSecretsManagerClient(AmazonSecretsManagerConfig config)
        : base(config)
    {
    }

    public PipelineSecretsManagerClient(AWSCredentials credentials, AmazonSecretsManagerConfig config)
        : base(credentials, config)
    {
    }

    protected override void CustomizeRuntimePipeline(RuntimePipeline pipeline)
    {
        base.CustomizeRuntimePipeline(pipeline);
        pipeline.AddHandlerAfter<Unmarshaller>(new PipelineSecretCaptureHandler());
    }
}

/// <summary>
/// Inside the unmarshaller, so it sees a successful response before it's parsed: for a
/// <see cref="PipelineGetSecretValueRequest"/>, reads the body off the network into pinned memory,
/// hands it to the request's capture, zeroes it, and gives the unmarshaller an empty object in its
/// place - nothing the writer needs is in the response. Every other response passes through.
/// </summary>
internal sealed class PipelineSecretCaptureHandler : PipelineHandler
{
    public override async Task<T> InvokeAsync<T>(IExecutionContext executionContext)
    {
        var result = await base.InvokeAsync<T>(executionContext).ConfigureAwait(false);

        // An error response has thrown inside base.InvokeAsync already, so this one succeeded.
        if (executionContext.RequestContext.OriginalRequest is PipelineGetSecretValueRequest request)
        {
            var response = executionContext.ResponseContext.HttpResponse;
            byte[] buffer;
            int length;
            using (var body = await response.ResponseBody.OpenResponseAsync().ConfigureAwait(false))
                (buffer, length) = await PinnedBody.ReadAsync(body, executionContext.RequestContext.CancellationToken).ConfigureAwait(false);

            try
            {
                request.Capture(buffer.AsSpan(0, length));
            }
            finally
            {
                ArrayUtility.ZeroMemory(buffer);
            }

            executionContext.ResponseContext.HttpResponse = new RedactedResponse(response, "{}"u8.ToArray());
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
