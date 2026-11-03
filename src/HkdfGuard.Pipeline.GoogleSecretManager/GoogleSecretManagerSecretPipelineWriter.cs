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
using HkdfGuard.Cache;

namespace HkdfGuard.Pipeline.GoogleSecretManager;

/// <summary>
/// The end of a provisioning pipeline: pulls a fixed list of secrets from one Google Cloud
/// project's Secret Manager, encrypts each with an IPipelineDataProtector as soon as it is read,
/// and writes them out as one file per secret - the folder layout <see cref="FilePerSecretCache"/>
/// reads at runtime. It is independent of HkdfGuard.Cache.GoogleSecretManager's runtime cache, and
/// of any key ring, with its own client. Naming, encrypting, keeping and writing are
/// <see cref="SecretPipelineWriter"/>'s.
/// <code>
/// using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
/// using var writer = GoogleSecretManagerSecretPipelineWriter.Create("my-project",
///     await GoogleCredential.GetApplicationDefaultAsync(), protector,
///     ["db-login#username", "db-login#password", "api-key"]);
/// await writer.PullSecretsAsync();
/// writer.WriteProtectedSecretFiles(@"C:\HkdfGuardSecrets\myapp");
/// // Then hand protector.GetKeyAsBase64() to the wrap tool, and register the key at version 3.
/// </code>
/// <para>
/// A secret name is a Secret Manager secret ID - 1-255 ASCII letters, digits, hyphens and
/// underscores - optionally with a key after '#': "api-key" reads the latest version's whole
/// payload, and "db-login#password" the password member of a payload holding a JSON object
/// (written as api-key and db-login__password). A member's string is read as its text; a number,
/// true or false as its JSON text. A payload that isn't UTF-8 text is refused: the protector
/// encrypts text. Each secret's latest version is read with AccessSecretVersion, so the principal
/// needs only <c>secretmanager.versions.access</c> (the Secret Manager Secret Accessor role), never
/// a list permission. On GKE, Workload Identity supplies the application default credential.
/// </para>
/// <para>
/// A payload whose CRC32C doesn't match the checksum Google returns, or a response naming a
/// different secret, is refused with a CryptographicException. The payload is encrypted straight
/// from the ByteString gRPC deserialized it into, which is then zeroed, refused or not; the
/// writer's client also zeroes the pooled buffer gRPC received the message into (see
/// ReceiveBufferScrubber). What can't be zeroed is below gRPC: the HTTP/2 stack's own buffers.
/// </para>
/// </summary>
public sealed class GoogleSecretManagerSecretPipelineWriter : SecretPipelineWriter
{
    /// <summary>The longest ID Secret Manager accepts for a secret.</summary>
    public const int MaxSecretNameLength = 255;

    private readonly SecretManagerServiceClient _client;
    private readonly string _projectId;
    private GrpcChannel? _channel;

    /// <param name="callInvoker">Makes every call to Secret Manager, e.g. over a channel the caller
    /// manages. The writer adds its own interceptor (see ReceiveBufferScrubber). Only
    /// AccessSecretVersion is called.</param>
    /// <param name="projectId">The project whose secrets are read: its ID or number.</param>
    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, each a secret ID with the key to read after
    /// '#' if any. Copied: a later change to the list isn't seen.</param>
    /// <exception cref="ArgumentNullException">callInvoker, projectId, protector or secretNames is null</exception>
    /// <exception cref="ArgumentException">projectId is empty, or holds anything but ASCII letters,
    /// digits, hyphens, dots and colons; or secretNames is empty, or holds a null, an ID Secret
    /// Manager can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or
    /// two with the same file name, in any case</exception>
    public GoogleSecretManagerSecretPipelineWriter(CallInvoker callInvoker, string projectId, IPipelineDataProtector protector,
        IList<string> secretNames)
        : base(protector, secretNames, IsValidSecretName)
    {
        ArgumentNullException.ThrowIfNull(callInvoker);
        ArgumentException.ThrowIfNullOrEmpty(projectId);

        // Spliced into every resource name, so nothing that could change the path is allowed.
        if (!projectId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or ':'))
            throw new ArgumentException($"'{projectId}' isn't a Google Cloud project ID or number.", nameof(projectId));

        _client = new SecretManagerServiceClientBuilder { CallInvoker = callInvoker.Intercept(new ReceiveBufferScrubber()) }.Build();
        _projectId = projectId;
    }

    /// <summary>A writer reading secrets over a new channel to Secret Manager, which disposing the writer disposes, authorized by credential.</summary>
    /// <param name="projectId">The project whose secrets are read: its ID or number.</param>
    /// <param name="credential">Authorizes every call, e.g. from
    /// <see cref="GoogleCredential.GetApplicationDefaultAsync(System.Threading.CancellationToken)"/>; scoped as Secret Manager needs.</param>
    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, as for the constructor.</param>
    /// <exception cref="ArgumentNullException">projectId, credential, protector or secretNames is null</exception>
    /// <exception cref="ArgumentException">As for the constructor</exception>
    public static GoogleSecretManagerSecretPipelineWriter Create(string projectId, GoogleCredential credential, IPipelineDataProtector protector,
        IList<string> secretNames)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var channel = GrpcChannel.ForAddress($"https://{SecretManagerServiceClient.DefaultEndpoint}", new GrpcChannelOptions
        {
            Credentials = credential.CreateScoped(SecretManagerServiceClient.DefaultScopes).ToChannelCredentials(),
        });
        try
        {
            return new GoogleSecretManagerSecretPipelineWriter(channel.CreateCallInvoker(), projectId, protector, secretNames) { _channel = channel };
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    /// <summary>Whether Secret Manager accepts name as a secret ID: 1-255 ASCII letters, digits, hyphens and underscores.</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>CRC32C (Castagnoli), as Secret Manager checksums payloads.</summary>
    internal static long Crc32C(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var b in data)
            crc = BitOperations.Crc32C(crc, b);
        return ~crc;
    }

    /// <summary>Disposes the channel <see cref="Create"/> made; a caller's own call invoker is left as it is.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _channel?.Dispose();
    }

    /// <inheritdoc/>
    /// <exception cref="RpcException">Any Secret Manager failure but NOT_FOUND (permission denied, a
    /// disabled or destroyed latest version, Google unreachable, no credentials)</exception>
    /// <exception cref="CryptographicException">The payload doesn't match its CRC32C, or the response
    /// names a different secret</exception>
    /// <exception cref="InvalidDataException">The payload isn't UTF-8 text, or a JSON object payload
    /// holds a key twice</exception>
    protected override async Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        AccessSecretVersionResponse response;
        try
        {
            response = await _client.AccessSecretVersionAsync(new SecretVersionName(_projectId, name, "latest"), cancellationToken).ConfigureAwait(false);
        }
        catch (RpcException e) when (e.StatusCode == StatusCode.NotFound)
        {
            // Missing: nothing handed over.
            return;
        }

        var payload = response.Payload?.Data ?? ByteString.Empty;
        try
        {
            CheckResponse(response, name, payload);
            ProtectSecret(payload.Span, requests, values);
        }
        finally
        {
            // The bytes gRPC deserialized the payload into, refused or not.
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
