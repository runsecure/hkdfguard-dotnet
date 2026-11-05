using System.Text.Json;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;

namespace HkdfGuard.Pipeline.AwsSecretsManager;

/// <summary>
/// The end of a provisioning pipeline: pulls a fixed list of secrets from AWS Secrets Manager,
/// encrypts each with an IPipelineDataProtector as soon as it is read, and writes them out as one
/// file per secret - the folder layout <see cref="FilePerSecretCache"/> reads at runtime. It is
/// independent of HkdfGuard.Cache.AwsSecretsManager's runtime cache, and of any key ring, with its
/// own client. Naming, encrypting, keeping and writing are <see cref="SecretPipelineWriter"/>'s.
/// <code>
/// using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
/// using var writer = new AwsSecretsManagerSecretPipelineWriter(protector,
///     ["prod/app#username", "prod/app#password", "prod/api-key"]);
/// await writer.PullSecretsAsync();
/// writer.WriteProtectedSecretFiles(@"C:\HkdfGuardSecrets\myapp");
/// // Then hand protector.GetKeyAsBase64() to the wrap tool, and register the key at version 3.
/// </code>
/// <para>
/// A secret name is a Secrets Manager secret name, optionally with a key after '#': "prod/api-key"
/// reads the secret's whole SecretString, and "prod/app#password" the password member of a
/// key/value secret - a SecretString holding a JSON object, as the console stores one (written as
/// prod__api-key and prod__app__password). A member's string is read as its text; a number, true or
/// false as its JSON text. Each secret's current version (AWSCURRENT) is read with GetSecretValue,
/// so the principal needs only <c>secretsmanager:GetSecretValue</c> on them (and <c>kms:Decrypt</c>
/// on a customer managed key that encrypts them). A name holding '+', '=' or '@', which no file name
/// can, is refused. A SecretBinary is refused: the protector encrypts text.
/// </para>
/// <para>
/// The writer's client reads the response body off the network into pinned memory and hands the
/// SDK's unmarshaller an empty object in its place, so the value never becomes the response's
/// SecretString; every buffer holding it is zeroed. Timeouts and retries are the client config's.
/// </para>
/// </summary>
public sealed class AwsSecretsManagerSecretPipelineWriter : SecretPipelineWriter
{
    /// <summary>The longest name Secrets Manager accepts for a secret.</summary>
    public const int MaxSecretNameLength = 512;

    private readonly AmazonSecretsManagerClient _client;

    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, each a secret name with the key to read after
    /// '#' if any. Copied: a later change to the list isn't seen.</param>
    /// <param name="config">Configures the writer's Secrets Manager client (region, timeouts,
    /// retries...); null for the defaults, which take the region from the environment or profile.</param>
    /// <param name="credentials">Authorizes every call; null for the SDK's default credential chain
    /// (environment, profile, IRSA or EKS Pod Identity, instance role...).</param>
    /// <exception cref="ArgumentNullException">protector or secretNames is null</exception>
    /// <exception cref="ArgumentException">secretNames is empty, or holds a null, a name Secrets
    /// Manager can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or
    /// two with the same file name, in any case</exception>
    public AwsSecretsManagerSecretPipelineWriter(IPipelineDataProtector protector, IList<string> secretNames,
        AmazonSecretsManagerConfig? config = null, AWSCredentials? credentials = null)
        : base(protector, secretNames, IsValidSecretName)
    {
        config ??= new AmazonSecretsManagerConfig();
        _client = credentials is null
            ? new PipelineSecretsManagerClient(config)
            : new PipelineSecretsManagerClient(credentials, config);
    }

    /// <summary>Whether Secrets Manager accepts name as a secret name: 1-512 ASCII letters, digits and /_+=.@-</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '/' or '_' or '+' or '=' or '.' or '@' or '-');

    /// <summary>The writer's own client, for tests to observe.</summary>
    internal AmazonSecretsManagerClient Client => _client;

    /// <summary>Disposes the writer's Secrets Manager client.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _client.Dispose();
    }

    /// <inheritdoc/>
    /// <exception cref="AmazonServiceException">Any AWS failure but ResourceNotFoundException (access
    /// denied, a secret scheduled for deletion, no credentials)</exception>
    /// <exception cref="InvalidDataException">The secret is a SecretBinary, the response isn't
    /// Secrets Manager's JSON, or a key/value secret holds a key twice</exception>
    protected override async Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        // Filled by the client's capture handler, from the body in pinned memory; the response the
        // SDK unmarshals holds nothing, so it isn't read here.
        var read = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var request = new PipelineGetSecretValueRequest(body =>
        {
            read.Clear();
            ProtectValues(body, requests, read);
        })
        {
            SecretId = name,
        };

        try
        {
            await _client.GetSecretValueAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (ResourceNotFoundException)
        {
            // Missing: nothing handed over.
            return;
        }

        foreach (var (fileName, value) in read)
            values.Add(fileName, value);
    }

    // Encrypts the top-level SecretString of a GetSecretValue body, and each requested key it holds.
    private void ProtectValues(ReadOnlySpan<byte> body, IReadOnlyList<SecretRequest> requests, Dictionary<string, string> values)
    {
        var reader = new Utf8JsonReader(body);
        try
        {
            if (!StartsObject(ref reader))
                throw new InvalidDataException("The response body isn't a JSON object.");

            while (NextProperty(ref reader))
            {
                var isText = reader.ValueTextEquals("SecretString");
                var isBinary = !isText && reader.ValueTextEquals("SecretBinary");
                reader.Read();
                if (reader.TokenType != JsonTokenType.String || reader.ValueSpan.IsEmpty || !(isText || isBinary))
                {
                    reader.Skip();
                    continue;
                }

                if (isBinary)
                    throw new InvalidDataException("A SecretBinary can't be protected: the pipeline protector encrypts text.");

                ProtectSecretString(ref reader, requests, values);
            }
        }
        catch (JsonException e)
        {
            // Not chained: the reader's message quotes the byte it rejected, which may be in the secret.
            throw new InvalidDataException($"The response body isn't valid JSON (at byte {e.BytePositionInLine} of line {e.LineNumber}).");
        }
    }

    // Unescapes the SecretString reader is at into pinned memory, and encrypts it whole and each
    // requested key it holds.
    private void ProtectSecretString(ref Utf8JsonReader reader, IReadOnlyList<SecretRequest> requests, Dictionary<string, string> values)
    {
        // Unescaped, a string is never longer than it is escaped.
        var text = ArrayUtility.AllocatePinned<byte>(reader.ValueSpan.Length);
        try
        {
            ProtectSecret(text.AsSpan(0, reader.CopyString(text)), requests, values);
        }
        finally
        {
            ArrayUtility.ZeroMemory(text);
        }
    }
}
