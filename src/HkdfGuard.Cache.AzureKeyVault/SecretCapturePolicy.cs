using Azure.Core;
using Azure.Core.Pipeline;

namespace HkdfGuard.Cache.AzureKeyVault;

/// <summary>
/// Takes the secret out of a Get Secret response before SecretClient can turn it into a string. Acts
/// only on a request made inside a <see cref="Scope"/>: it stops Azure.Core buffering that response,
/// so the body comes straight off the network into <see cref="SecretJsonBody"/>'s pinned memory -
/// read asynchronously on the asynchronous pipeline - hands its <c>value</c> to the scope's sink,
/// and gives SecretClient the body with <c>value</c> blanked. Any other response is buffered as
/// Azure.Core would have, for SecretClient's error handling.
/// </summary>
internal sealed class SecretCapturePolicy : HttpPipelinePolicy
{
    private const string SinkProperty = "HkdfGuard.Cache.AzureKeyVault.SecretValueSink";

    public static readonly SecretCapturePolicy Instance = new();

    /// <summary>Requests made until the scope is disposed hand their secret to value.</summary>
    public static IDisposable Scope(SecretValueSink value)
        => HttpPipeline.CreateHttpMessagePropertiesScope(new Dictionary<string, object?> { [SinkProperty] = value });

    public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        var sink = Unbuffered(message);
        ProcessNext(message, pipeline);
        if (sink is null || message.Response.ContentStream is not { } body)
            return;

        using (body)
        {
            if (message.Response.Status == 200)
            {
                message.Response.ContentStream = new MemoryStream(SecretJsonBody.Capture(body, sink, "value"));
            }
            else
            {
                var buffered = new MemoryStream();
                body.CopyTo(buffered);
                buffered.Position = 0;
                message.Response.ContentStream = buffered;
            }
        }
    }

    public override async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        var sink = Unbuffered(message);
        await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
        if (sink is null || message.Response.ContentStream is not { } body)
            return;

        await using (body.ConfigureAwait(false))
        {
            if (message.Response.Status == 200)
            {
                message.Response.ContentStream = new MemoryStream(
                    await SecretJsonBody.CaptureAsync(body, sink, "value", cancellationToken: message.CancellationToken).ConfigureAwait(false));
            }
            else
            {
                var buffered = new MemoryStream();
                await body.CopyToAsync(buffered, message.CancellationToken).ConfigureAwait(false);
                buffered.Position = 0;
                message.Response.ContentStream = buffered;
            }
        }
    }

    // The scope's sink, if the request was made inside one, its response then left unbuffered.
    private static SecretValueSink? Unbuffered(HttpMessage message)
    {
        if (!message.TryGetProperty(SinkProperty, out var sink))
            return null;

        message.BufferResponse = false;
        return (SecretValueSink)sink!;
    }
}
