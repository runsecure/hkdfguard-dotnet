using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;

namespace HkdfGuard.Pipeline.AzureKeyVault;

/// <summary>
/// The end of a provisioning pipeline: pulls a fixed list of secrets from one Azure Key Vault,
/// encrypts each with an IPipelineDataProtector as soon as it is read, and writes them out as one
/// file per secret - the folder layout <see cref="FilePerSecretCache"/> reads at runtime. It is
/// independent of HkdfGuard.Cache.AzureKeyVault's runtime cache, and of any key ring, with its own
/// SecretClient. Naming, encrypting, keeping and writing are <see cref="SecretPipelineWriter"/>'s.
/// <code>
/// using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
/// using var writer = new AzureKeyVaultSecretPipelineWriter(vaultUri, new DefaultAzureCredential(), protector,
///     ["Db-Login#username", "Db-Login#password", "Api-Key"]);
/// await writer.PullSecretsAsync();
/// writer.WriteProtectedSecretFiles(@"C:\HkdfGuardSecrets\myapp");
/// // Then hand protector.GetKeyAsBase64() to the wrap tool, and register the key at version 3.
/// </code>
/// <para>
/// A secret name is a Key Vault secret name - 1-127 ASCII letters, digits and hyphens - optionally
/// with a key after '#': "Api-Key" reads the secret's whole value, and "Db-Login#password" the
/// password member of a secret whose value is a JSON object (written as Api-Key and
/// Db-Login__password). A member's string is read as its text; a number, true or false as its JSON
/// text. Each secret's current version is read with Get Secret, so the principal needs only
/// <c>get</c> on secrets (the Key Vault Secrets User role), never <c>list</c>. Key Vault compares
/// names ignoring case; so do file names, so two names differing only in case are refused.
/// </para>
/// <para>
/// The writer's SecretClient has a pipeline policy that reads the response body off the network
/// into pinned memory and hands SecretClient an empty object in its place, so the value never
/// becomes a KeyVaultSecret's string; every buffer holding it is zeroed. Retries and timeouts are
/// the client options'. On AKS, Microsoft Entra Workload Identity supplies the credential through
/// DefaultAzureCredential or WorkloadIdentityCredential.
/// </para>
/// </summary>
public sealed class AzureKeyVaultSecretPipelineWriter : SecretPipelineWriter
{
    /// <summary>The longest name Key Vault accepts for a secret.</summary>
    public const int MaxSecretNameLength = 127;

    private readonly SecretClient _client;

    /// <param name="vaultUri">The vault to read secrets from: https://{vault}.vault.azure.net/</param>
    /// <param name="credential">Authenticates every call to Key Vault, e.g. a managed or workload identity.</param>
    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, each a secret name with the key to read after
    /// '#' if any. Copied: a later change to the list isn't seen.</param>
    /// <param name="options">Options for the writer's Key Vault client; null for the defaults. The
    /// writer adds its own pipeline policy to this instance - the SDK has no way to copy one - so
    /// the caller's object is changed; the policy acts only on the writer's own reads. Prefer a fresh
    /// instance per writer.</param>
    /// <exception cref="ArgumentNullException">vaultUri, credential, protector or secretNames is null</exception>
    /// <exception cref="ArgumentException">secretNames is empty, or holds a null, a name Key Vault
    /// can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or two with
    /// the same file name, in any case; or options log response content, which would log every
    /// secret's value</exception>
    public AzureKeyVaultSecretPipelineWriter(Uri vaultUri, TokenCredential credential, IPipelineDataProtector protector,
        IList<string> secretNames, SecretClientOptions? options = null)
        : base(protector, secretNames, IsValidSecretName)
    {
        ArgumentNullException.ThrowIfNull(vaultUri);
        ArgumentNullException.ThrowIfNull(credential);
        options ??= new SecretClientOptions();
        if (options.Diagnostics.IsLoggingContentEnabled)
            throw new ArgumentException("Logging response content would log every secret's value; turn it off for this client.", nameof(options));

        options.AddPolicy(PipelineSecretCapturePolicy.Instance, HttpPipelinePosition.PerRetry);
        _client = new SecretClient(vaultUri, credential, options);
    }

    /// <summary>Whether Key Vault accepts name as a secret name: 1-127 ASCII letters, digits and hyphens.</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    /// <inheritdoc/>
    /// <exception cref="RequestFailedException">Any Key Vault failure but 404 (access denied, a
    /// disabled secret, the vault unreachable); a credential that can't get a token throws its own
    /// exception</exception>
    /// <exception cref="InvalidDataException">The response isn't Key Vault's JSON, or a JSON object
    /// value holds a key twice</exception>
    protected override async Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        // Filled by the client's capture policy, from the body in pinned memory, once per attempt;
        // what SecretClient returns holds nothing, so it isn't read here.
        var read = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (PipelineSecretCapturePolicy.Scope(body =>
               {
                   read.Clear();
                   ProtectValues(body, requests, read);
               }))
        {
            try
            {
                await _client.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (RequestFailedException e) when (e.Status == 404)
            {
                // Missing: nothing handed over.
                return;
            }
        }

        foreach (var (fileName, value) in read)
            values.Add(fileName, value);
    }

    // Encrypts the top-level value of a Get Secret body, and each requested key it holds.
    private void ProtectValues(ReadOnlySpan<byte> body, IReadOnlyList<SecretRequest> requests, Dictionary<string, string> values)
    {
        var reader = new Utf8JsonReader(body);
        try
        {
            if (!StartsObject(ref reader))
                throw new InvalidDataException("The response body isn't a JSON object.");

            while (NextProperty(ref reader))
            {
                var isValue = reader.ValueTextEquals("value");
                reader.Read();
                if (!isValue || reader.TokenType != JsonTokenType.String)
                {
                    reader.Skip();
                    continue;
                }

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
        catch (JsonException e)
        {
            // Not chained: the reader's message quotes the byte it rejected, which may be in the secret.
            throw new InvalidDataException($"The response body isn't valid JSON (at byte {e.BytePositionInLine} of line {e.LineNumber}).");
        }
    }
}
