using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.AzureKeyVault;

/// <summary>
/// An IProtectedReadOnlyCache over the secrets in one Azure Key Vault. The first lookup of a name
/// that isn't cached yet reads that one secret (its current version) with GetSecret; fetching,
/// encryption, caching and telemetry are RemoteSecretCache's. This class never lists the vault's
/// secrets, so the principal needs only <c>get</c> on secrets (the Key Vault Secrets User role),
/// never <c>list</c>.
/// <para>
/// Key Vault secret names are 1-127 ASCII letters, digits and hyphens, compared ignoring case, so
/// "Db-Password" and "DB-PASSWORD" are one entry and one secret. Any other name (a configuration
/// path such as "ConnectionStrings:Admin", say) is reported missing without a call - and is never
/// spliced into a request URL.
/// </para>
/// <para>
/// A secret whose value is a JSON object, such as {"username":"app","password":"..."}, is cached
/// whole under its name and each member under "name#key" - "Db-Login#password" - all from one call
/// (see RemoteSecretCache). Keys are matched exactly, though secret names aren't.
/// </para>
/// <para>
/// A secret that doesn't exist (404) or whose value is empty is reported missing. Any other failure
/// (access denied, a disabled secret, the vault unreachable, a credential that can't get a token)
/// propagates as the Azure exception.
/// </para>
/// <para>
/// The secret never becomes a string. The cache makes its own SecretClient with a pipeline policy
/// (SecretCapturePolicy) that reads the response body off the network into pinned memory, takes the
/// value out of it, and hands SecretClient the body with the value blanked; every buffer holding the
/// value is zeroed. What can't be zeroed is below the pipeline: the HTTP stack's own buffers (TLS
/// decryption, socket reads). DecryptAsync and GetMaxDecryptedLengthAsync fetch with GetSecretAsync,
/// so a miss doesn't block a thread.
/// </para>
/// </summary>
public sealed class AzureKeyVaultSecretCache : RemoteSecretCache
{
    /// <summary>The longest name Key Vault accepts for a secret.</summary>
    public const int MaxSecretNameLength = 127;

    private readonly SecretClient _client;

    /// <param name="vaultUri">The vault to read secrets from: https://{vault}.vault.azure.net/</param>
    /// <param name="credential">Authenticates every call to Key Vault, e.g. a managed identity.</param>
    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="options">Options for the cache's Key Vault client; null for the defaults. The
    /// cache adds its own pipeline policy to them.</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">vaultUri, credential or keyRing is null</exception>
    /// <exception cref="ArgumentException">options log response content, which would log every
    /// secret's value</exception>
    public AzureKeyVaultSecretCache(Uri vaultUri, TokenCredential credential, IKeyRing keyRing,
        SecretClientOptions? options = null, ILogger<AzureKeyVaultSecretCache>? logger = null)
        : base(keyRing, SecretNameMatching.IgnoreAsciiCase, logger)
    {
        options ??= new SecretClientOptions();
        if (options.Diagnostics.IsLoggingContentEnabled)
            throw new ArgumentException("Logging response content would log every secret's value; turn it off for this client.", nameof(options));

        options.AddPolicy(SecretCapturePolicy.Instance, HttpPipelinePosition.PerRetry);
        _client = new SecretClient(vaultUri, credential, options);
    }

    /// <summary>Whether Key Vault accepts name as a secret name: 1-127 ASCII letters, digits and hyphens.</summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxSecretNameLength
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');

    /// <inheritdoc/>
    protected override bool IsValidName(string name) => IsValidSecretName(name);

    /// <inheritdoc/>
    protected override void Fetch(string name, SecretValueSink value)
    {
        // The value reaches the sink through SecretCapturePolicy; what SecretClient returns holds it
        // blanked, so it isn't read here.
        using (SecretCapturePolicy.Scope(value))
        {
            try
            {
                _client.GetSecret(name);
            }
            catch (RequestFailedException e) when (e.Status == 404)
            {
                // Missing: nothing handed over.
            }
        }
    }

    /// <inheritdoc/>
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        // As Fetch, on SecretClient's asynchronous pipeline; the scope flows into it.
        using (SecretCapturePolicy.Scope(value))
        {
            try
            {
                await _client.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            catch (RequestFailedException e) when (e.Status == 404)
            {
                // Missing: nothing handed over.
            }
        }
    }
}
