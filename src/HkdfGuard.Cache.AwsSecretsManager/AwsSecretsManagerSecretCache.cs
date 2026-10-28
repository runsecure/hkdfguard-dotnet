using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.AwsSecretsManager;

/// <summary>
/// An IProtectedReadOnlyCache over the secrets in AWS Secrets Manager. The first lookup of a name
/// that isn't cached yet reads that one secret's current version (AWSCURRENT) with GetSecretValue;
/// fetching, encryption, caching and telemetry are RemoteSecretCache's. This class never lists
/// secrets (ListSecrets, BatchGetSecretValue), so the principal needs only
/// <c>secretsmanager:GetSecretValue</c> on the secrets it reads (and <c>kms:Decrypt</c> on a
/// customer managed key that encrypts them).
/// <para>
/// Names are matched exactly, as Secrets Manager matches them: "prod/Db" and "prod/db" are two
/// secrets and two entries. A name Secrets Manager can't hold - anything but 1-512 ASCII letters,
/// digits and /_+=.@- , such as the configuration path "ConnectionStrings:Admin" - is reported
/// missing without a call. ARNs aren't accepted: look secrets up by name.
/// </para>
/// <para>
/// A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is reported
/// missing. Any other failure (access denied, a secret scheduled for deletion, AWS unreachable, no
/// credentials) propagates as the AWS exception. A SecretString is cached as its UTF-8 bytes; a
/// SecretBinary as its bytes.
/// </para>
/// <para>
/// A key/value secret - a SecretString holding a JSON object, as the console stores one - is cached
/// whole under its name and each member under "name#key" - "prod/app#password" - all from one
/// GetSecretValue (see RemoteSecretCache). A SecretBinary is never split.
/// </para>
/// <para>
/// A fetch is asynchronous through DecryptAsync and GetMaxDecryptedLengthAsync. The AWS SDK for .NET
/// has only asynchronous calls, so through Decrypt and TryGetMaxDecryptedLength a fetch blocks the
/// calling thread (off any SynchronizationContext) until AWS answers; set timeouts and retries on
/// the client's config.
/// </para>
/// <para>
/// The secret never becomes a string. The cache makes its own client, whose pipeline reads the
/// response body off the network into pinned memory, takes SecretString or SecretBinary out of it,
/// and hands the SDK's unmarshaller the body with both blanked; every buffer holding the value is
/// zeroed. What can't be zeroed is below the pipeline: the HTTP stack's own buffers (TLS decryption,
/// socket reads). Dispose the cache to dispose its client.
/// </para>
/// </summary>
public sealed class AwsSecretsManagerSecretCache : RemoteSecretCache, IDisposable
{
    /// <summary>The longest name Secrets Manager accepts for a secret.</summary>
    public const int MaxSecretNameLength = 512;

    private readonly AmazonSecretsManagerClient _client;

    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="config">Configures the cache's Secrets Manager client (region, timeouts,
    /// retries...); null for the defaults, which take the region from the environment or profile.</param>
    /// <param name="credentials">Authorizes every call; null for the SDK's default credential chain.</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">keyRing is null</exception>
    public AwsSecretsManagerSecretCache(IKeyRing keyRing, AmazonSecretsManagerConfig? config = null, AWSCredentials? credentials = null,
        ILogger<AwsSecretsManagerSecretCache>? logger = null)
        : base(keyRing, SecretNameMatching.Exact, logger)
    {
        config ??= new AmazonSecretsManagerConfig();
        _client = credentials is null
            ? new CapturingSecretsManagerClient(config)
            : new CapturingSecretsManagerClient(credentials, config);
    }

    /// <summary>Whether Secrets Manager accepts name as a secret name: 1-512 ASCII letters, digits and /_+=.@-</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '/' or '_' or '+' or '=' or '.' or '@' or '-');

    /// <inheritdoc/>
    protected override bool IsValidName(string name) => IsValidSecretName(name);

    /// <inheritdoc/>
    protected override void Fetch(string name, SecretValueSink value)
        // Off the caller's SynchronizationContext, so blocking on it can't deadlock.
        => Task.Run(() => FetchAsync(name, value, CancellationToken.None).AsTask()).GetAwaiter().GetResult();

    /// <inheritdoc/>
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        // The value reaches the sink through the client's SecretCaptureHandler; the response holds
        // it blanked, so it isn't read here.
        var request = new CapturingGetSecretValueRequest(value) { SecretId = name };
        try
        {
            (await _client.GetSecretValueAsync(request, cancellationToken).ConfigureAwait(false)).SecretBinary?.Dispose();
        }
        catch (ResourceNotFoundException)
        {
            // Missing: nothing handed over.
        }
    }

    /// <summary>The cache's own client, for tests to observe.</summary>
    internal AmazonSecretsManagerClient Client => _client;

    /// <summary>Disposes the cache's Secrets Manager client.</summary>
    public void Dispose() => _client.Dispose();
}
