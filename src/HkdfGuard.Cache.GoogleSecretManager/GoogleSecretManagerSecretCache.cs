using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Google.Apis.Auth.OAuth2;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Auth;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.GoogleSecretManager;

/// <summary>
/// An IProtectedReadOnlyCache over the secrets in one Google Cloud project's Secret Manager. The
/// first lookup of a name that isn't cached yet reads that one secret's latest version with
/// AccessSecretVersion; fetching, encryption, caching and telemetry are RemoteSecretCache's. This
/// class never lists secrets or versions, so the principal needs only
/// <c>secretmanager.versions.access</c> on the secrets it reads (the Secret Manager Secret Accessor
/// role), never <c>secretmanager.secrets.list</c>.
/// <para>
/// Names are matched exactly, as Secret Manager matches secret IDs: "Db-Password" and "db-password"
/// are two secrets and two entries. A name Secret Manager can't hold - anything but 1-255 ASCII
/// letters, digits, hyphens and underscores, such as the configuration path
/// "ConnectionStrings:Admin" - is reported missing without a call.
/// </para>
/// <para>
/// A payload holding a JSON object, such as {"username":"app","password":"..."}, is cached whole
/// under the secret's ID and each member under "id#key" - "Db-Login#password" - all from one call
/// (see RemoteSecretCache).
/// </para>
/// <para>
/// A secret that doesn't exist, or has no versions (NOT_FOUND), or whose value is empty is reported
/// missing. Any other failure (permission denied, a disabled or destroyed latest version, Google
/// unreachable, no credentials) propagates as the gRPC RpcException. A payload whose CRC32C doesn't
/// match the checksum Google returns, or a response naming a different secret, is refused with a
/// CryptographicException.
/// </para>
/// <para>
/// The secret never becomes a string. Its payload arrives as protobuf bytes: the cache encrypts them
/// straight from the ByteString they were deserialized into and then zeroes it, refused or not. The
/// cache's client also zeroes the pooled buffer gRPC received the message into (see
/// ReceiveBufferScrubber), which gRPC would otherwise return to the shared ArrayPool uncleared. What
/// can't be zeroed is below gRPC: the HTTP/2 stack's own buffers (TLS decryption, socket reads).
/// DecryptAsync and GetMaxDecryptedLengthAsync fetch with AccessSecretVersionAsync, so a miss doesn't
/// block a thread.
/// </para>
/// </summary>
public sealed class GoogleSecretManagerSecretCache : RemoteSecretCache, IDisposable
{
    /// <summary>The longest ID Secret Manager accepts for a secret.</summary>
    public const int MaxSecretNameLength = 255;

    private readonly SecretManagerServiceClient _client;
    private readonly string _projectId;
    private GrpcChannel? _channel;

    /// <summary>A cache reading secrets over a new channel, which disposing the cache disposes to Secret Manager, authorized by credential.</summary>
    /// <param name="projectId">The project whose secrets are read: its ID or number.</param>
    /// <param name="credential">Authorizes every call, e.g. from
    /// <see cref="GoogleCredential.GetApplicationDefaultAsync(System.Threading.CancellationToken)"/>; scoped as Secret Manager needs.</param>
    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">projectId, credential or keyRing is null</exception>
    /// <exception cref="ArgumentException">projectId isn't a project ID or number</exception>
    public static GoogleSecretManagerSecretCache Create(string projectId, GoogleCredential credential, IKeyRing keyRing,
        ILogger<GoogleSecretManagerSecretCache>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var channel = GrpcChannel.ForAddress($"https://{SecretManagerServiceClient.DefaultEndpoint}", new GrpcChannelOptions
        {
            Credentials = credential.CreateScoped(SecretManagerServiceClient.DefaultScopes).ToChannelCredentials(),
        });
        try
        {
            return new GoogleSecretManagerSecretCache(channel.CreateCallInvoker(), projectId, keyRing, logger) { _channel = channel };
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    /// <param name="callInvoker">Makes every call to Secret Manager, e.g. over a channel the caller
    /// manages. The cache adds its own interceptor (see ReceiveBufferScrubber). Only
    /// AccessSecretVersion is called.</param>
    /// <param name="projectId">The project whose secrets are read: its ID or number.</param>
    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">callInvoker, projectId or keyRing is null</exception>
    /// <exception cref="ArgumentException">projectId is empty, or holds anything but ASCII letters,
    /// digits, hyphens, dots and colons</exception>
    public GoogleSecretManagerSecretCache(CallInvoker callInvoker, string projectId, IKeyRing keyRing,
        ILogger<GoogleSecretManagerSecretCache>? logger = null)
        : base(keyRing, SecretNameMatching.Exact, logger)
    {
        ArgumentNullException.ThrowIfNull(callInvoker);
        ArgumentException.ThrowIfNullOrEmpty(projectId);

        // Spliced into every resource name, so nothing that could change the path is allowed.
        if (!projectId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or ':'))
            throw new ArgumentException($"'{projectId}' isn't a Google Cloud project ID or number.", nameof(projectId));

        _client = new SecretManagerServiceClientBuilder { CallInvoker = callInvoker.Intercept(new ReceiveBufferScrubber()) }.Build();
        _projectId = projectId;
    }

    /// <summary>Whether Secret Manager accepts name as a secret ID: 1-255 ASCII letters, digits, hyphens and underscores.</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>Disposes the channel <see cref="Create"/> made; a caller's own call invoker is left as it is.</summary>
    public void Dispose() => _channel?.Dispose();

    /// <summary>CRC32C (Castagnoli), as Secret Manager checksums payloads.</summary>
    internal static long Crc32C(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var b in data)
            crc = BitOperations.Crc32C(crc, b);
        return ~crc;
    }

    /// <inheritdoc/>
    protected override bool IsValidName(string name) => IsValidSecretName(name);

    /// <inheritdoc/>
    protected override void Fetch(string name, SecretValueSink value)
    {
        AccessSecretVersionResponse response;
        try
        {
            response = _client.AccessSecretVersion(new SecretVersionName(_projectId, name, "latest"));
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.NotFound)
        {
            return;
        }

        Accept(response, name, value);
    }

    /// <inheritdoc/>
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        AccessSecretVersionResponse response;
        try
        {
            response = await _client.AccessSecretVersionAsync(new SecretVersionName(_projectId, name, "latest"), cancellationToken).ConfigureAwait(false);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.NotFound)
        {
            return;
        }

        Accept(response, name, value);
    }

    // Checks the response, hands its payload to value, and zeroes the payload either way.
    private static void Accept(AccessSecretVersionResponse response, string name, SecretValueSink value)
    {
        var payload = response.Payload?.Data ?? ByteString.Empty;
        try
        {
            CheckResponse(response, name, payload);

            // Zeroes what it's given: here, the bytes gRPC deserialized the payload into. A payload
            // holding a JSON object is cached whole and by key.
            value.SetBytesWithJsonKeys(MemoryMarshal.AsMemory(payload.Memory).Span);
        }
        finally
        {
            // Covers a refused response, which never reaches SetBytes.
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(payload.Memory).Span);
        }
    }

    // The response must be a version of the secret asked for (its project comes back as a number,
    // so only the secret ID can be compared), and match its checksum when it has one.
    private static void CheckResponse(AccessSecretVersionResponse response, string name, ByteString payload)
    {
        if (!SecretVersionName.TryParse(response.Name, out var version) || version.SecretId != name)
            throw new CryptographicException($"Secret Manager answered a request for secret '{name}' with '{response.Name}'.");

        if (response.Payload is { HasDataCrc32C: true } && response.Payload.DataCrc32C != Crc32C(payload.Span))
            throw new CryptographicException($"The payload of secret '{name}' doesn't match its CRC32C: it was corrupted in transit.");
    }
}
