using Azure.Core;
using Azure.Core.Pipeline;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Pipeline.AzureKeyVault;

/// <summary>Takes a successful Get Secret response body, in pinned memory zeroed once this returns.</summary>
internal delegate void SecretBodyCapture(ReadOnlySpan<byte> body);

/// <summary>
/// Takes the secret out of a Get Secret response before SecretClient can turn it into a string. Acts
/// only on a request made inside a <see cref="Scope"/>: it stops Azure.Core buffering that response,
/// so a 200's body comes straight off the network into pinned memory, is handed to the scope's
/// capture and zeroed, and SecretClient is given an empty object in its place - nothing the writer
/// needs is in the response. Any other response is buffered as Azure.Core would have, for
/// SecretClient's error handling. The writer reads only asynchronously, so a request inside a scope
/// on the synchronous pipeline is refused.
/// </summary>
internal sealed class PipelineSecretCapturePolicy : HttpPipelinePolicy
{
    private const string CaptureProperty = "HkdfGuard.Pipeline.AzureKeyVault.SecretBodyCapture";

    public static readonly PipelineSecretCapturePolicy Instance = new();

    /// <summary>Requests made until the scope is disposed hand their response body to capture.</summary>
    public static IDisposable Scope(SecretBodyCapture capture)
        => HttpPipeline.CreateHttpMessagePropertiesScope(new Dictionary<string, object?> { [CaptureProperty] = capture });

    public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        if (message.TryGetProperty(CaptureProperty, out _))
            throw new NotSupportedException("The pipeline writer reads secrets asynchronously only.");

        ProcessNext(message, pipeline);
    }

    public override async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
    {
        if (!message.TryGetProperty(CaptureProperty, out var property))
        {
            await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            return;
        }

        message.BufferResponse = false;
        await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
        if (message.Response.ContentStream is not { } body)
            return;

        await using (body.ConfigureAwait(false))
        {
            if (message.Response.Status != 200)
            {
                var buffered = new MemoryStream();
                await body.CopyToAsync(buffered, message.CancellationToken).ConfigureAwait(false);
                buffered.Position = 0;
                message.Response.ContentStream = buffered;
                return;
            }

            var (buffer, length) = await PinnedBody.ReadAsync(body, message.CancellationToken).ConfigureAwait(false);
            try
            {
                ((SecretBodyCapture)property!)(buffer.AsSpan(0, length));
            }
            finally
            {
                ArrayUtility.ZeroMemory(buffer);
            }

            message.Response.ContentStream = new MemoryStream("{}"u8.ToArray());
        }
    }
}
