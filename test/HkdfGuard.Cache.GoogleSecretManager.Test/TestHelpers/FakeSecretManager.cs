using System.Buffers;
using System.Collections.Concurrent;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;

namespace HkdfGuard.Cache.GoogleSecretManager.Test.TestHelpers;

/// <summary>
/// Secret Manager at the gRPC call level, behind the cache's real gax client and interceptor: an
/// AccessSecretVersion response is serialized into a receive buffer, as gRPC would read it off the
/// wire, and deserialized through the call's own response marshaller, so a test can check what was
/// left in that buffer afterwards. Secret IDs are matched exactly, as Google matches them. Any other
/// call - ListSecrets and ListSecretVersions among them - is recorded and refused. Responses carry a
/// CRC32C, as Google's do for payloads added with one.
/// </summary>
internal sealed class FakeSecretManager : CallInvoker
{
    public const string ProjectId = "hkdfguard-test";

    // Google answers with the project's number, not the ID it was asked with.
    private const string ProjectNumber = "123456789012";

    private const string AccessSecretVersion = "/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion";

    private readonly ConcurrentDictionary<string, byte[]> _secrets = new(StringComparer.Ordinal);

    /// <summary>Every resource name AccessSecretVersion was called with, in order.</summary>
    public ConcurrentQueue<string> Accesses { get; } = new();

    /// <summary>The secret ID of every access, in order.</summary>
    public IEnumerable<string> Gets => Accesses.Select(a => SecretVersionName.Parse(a).SecretId);

    /// <summary>Every other call, by method name.</summary>
    public ConcurrentQueue<string> UnexpectedCalls { get; } = new();

    /// <summary>When set, AccessSecretVersion fails with this instead of answering.</summary>
    public RpcException? Failure { get; set; }

    /// <summary>Runs inside every AccessSecretVersion before it answers, e.g. to hold it open.</summary>
    public Action? OnGet { get; set; }

    /// <summary>Rewrites a response before it is sent.</summary>
    public Action<AccessSecretVersionResponse>? Tamper { get; set; }

    /// <summary>Every receive buffer a response was deserialized from, to check it was zeroed.</summary>
    public ConcurrentQueue<byte[]> ReceiveBuffers { get; } = new();

    /// <summary>Every payload deserialized, to check the cache zeroed it.</summary>
    public ConcurrentQueue<ByteString> Payloads { get; } = new();

    public void Set(string secretId, byte[] value) => _secrets[secretId] = value;

    public void Set(string secretId, string value) => Set(secretId, System.Text.Encoding.UTF8.GetBytes(value));

    public override TResponse BlockingUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request)
    {
        if (method.FullName != AccessSecretVersion)
        {
            UnexpectedCalls.Enqueue(method.FullName);
            throw new RpcException(new Status(StatusCode.PermissionDenied, "Not allowed in a test."));
        }

        var response = Answer((AccessSecretVersionRequest)(object)request);
        var received = response.ToByteArray();
        ReceiveBuffers.Enqueue(received);

        var deserialized = method.ResponseMarshaller.ContextualDeserializer(new Received(received));
        if (deserialized is AccessSecretVersionResponse { Payload: { } payload })
            Payloads.Enqueue(payload.Data);
        return deserialized;
    }

    private AccessSecretVersionResponse Answer(AccessSecretVersionRequest request)
    {
        Accesses.Enqueue(request.Name);
        OnGet?.Invoke();
        if (Failure is not null)
            throw Failure;

        var name = SecretVersionName.Parse(request.Name);
        Assert.Equal(ProjectId, name.ProjectId);
        Assert.Equal("latest", name.SecretVersionId);
        if (!_secrets.TryGetValue(name.SecretId, out var value))
            throw new RpcException(new Status(StatusCode.NotFound, $"Secret [projects/{ProjectNumber}/secrets/{name.SecretId}] not found or has no versions."));

        var response = new AccessSecretVersionResponse
        {
            Name = new SecretVersionName(ProjectNumber, name.SecretId, "1").ToString(),
            Payload = new SecretPayload
            {
                Data = ByteString.CopyFrom(value),
                DataCrc32C = GoogleSecretManagerSecretCache.Crc32C(value),
            },
        };
        Tamper?.Invoke(response);
        return response;
    }

    /// <summary>How many calls were made asynchronously.</summary>
    public int AsyncCalls => _asyncCalls;

    private int _asyncCalls;

    // Answered as BlockingUnaryCall answers, through the same receive buffer and response marshaller.
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request)
    {
        Interlocked.Increment(ref _asyncCalls);
        Task<TResponse> response;
        try
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            response = Task.FromResult(BlockingUnaryCall(method, host, options, request));
        }
        catch (OperationCanceledException)
        {
            response = Task.FromException<TResponse>(new RpcException(new Status(StatusCode.Cancelled, "Cancelled by the caller.")));
        }
        catch (Exception e)
        {
            response = Task.FromException<TResponse>(e);
        }

        return new AsyncUnaryCall<TResponse>(response, Task.FromResult(new Metadata()), () => Status.DefaultSuccess, () => [], () => { });
    }

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options, TRequest request)
        => throw Unexpected(method);

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options)
        => throw Unexpected(method);

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(Method<TRequest, TResponse> method, string? host, CallOptions options)
        => throw Unexpected(method);

    private RpcException Unexpected(IMethod method)
    {
        UnexpectedCalls.Enqueue(method.FullName);
        return new RpcException(new Status(StatusCode.PermissionDenied, "Not allowed in a test."));
    }

    // A message as gRPC hands it to a deserializer: a view of the buffer it was received into.
    private sealed class Received(byte[] buffer) : DeserializationContext
    {
        public override int PayloadLength => buffer.Length;

        public override byte[] PayloadAsNewBuffer() => buffer.ToArray();

        public override ReadOnlySequence<byte> PayloadAsReadOnlySequence() => new(buffer);
    }
}
