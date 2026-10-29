using System.Net;
using Amazon.Runtime.EventStreams;
using Amazon.Runtime.Internal.Transform;

namespace HkdfGuard.Cache.AwsSecretsManager.Test;

/// <summary>The redacted response passes everything but its body through to the original response.</summary>
public class RedactedResponseTests
{
    [Fact]
    public void EverythingButTheBody_IsTheOriginalResponses()
    {
        var original = new StubResponse();
        using var redacted = new RedactedResponse(original, [1, 2, 3]);

        Assert.Equal(3, redacted.ContentLength);
        Assert.Equal("application/x-amz-json-1.1", redacted.ContentType);
        Assert.Equal(HttpStatusCode.OK, redacted.StatusCode);
        Assert.True(redacted.IsSuccessStatusCode);
        Assert.Equal(["x-amzn-RequestId"], redacted.GetHeaderNames());
        Assert.True(redacted.IsHeaderPresent("x-amzn-RequestId"));
        Assert.Equal("request-1", redacted.GetHeaderValue("x-amzn-RequestId"));
        Assert.Null(redacted.GetEventStreamHeader("any"));
        Assert.False(redacted.IsEventHeaderPresent("any"));
    }

    [Fact]
    public async Task TheBody_IsTheRedactedOne_AndDisposingDisposesTheOriginals()
    {
        var original = new StubResponse();
        var redacted = new RedactedResponse(original, [1, 2, 3]);

        using (var body = redacted.ResponseBody.OpenResponse())
            Assert.Equal(3, body.Length);
        using (var body = await redacted.ResponseBody.OpenResponseAsync())
            Assert.Equal(3, body.Length);

        redacted.Dispose();
        Assert.True(original.Disposed);
    }

    private sealed class StubResponse : IWebResponseData, IHttpResponseBody
    {
        public bool Disposed { get; private set; }
        public long ContentLength => 999;
        public string ContentType => "application/x-amz-json-1.1";
        public HttpStatusCode StatusCode => HttpStatusCode.OK;
        public bool IsSuccessStatusCode => true;
        public IHttpResponseBody ResponseBody => this;
        public string[] GetHeaderNames() => ["x-amzn-RequestId"];
        public bool IsHeaderPresent(string headerName) => headerName == "x-amzn-RequestId";
        public string GetHeaderValue(string headerName) => "request-1";
        public IEventStreamHeader GetEventStreamHeader(string headerName) => null!;
        public bool IsEventHeaderPresent(string headerName) => false;
        public Stream OpenResponse() => throw new InvalidOperationException("The original body must not be read again.");
        public Task<Stream> OpenResponseAsync() => throw new InvalidOperationException("The original body must not be read again.");
        public void Dispose() => Disposed = true;
    }
}
