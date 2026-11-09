using System.Net;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;
using HkdfGuard.Integration.HashiCorpVault;

namespace HkdfGuard.Pipeline.HashiCorpVault;

/// <summary>
/// The end of a provisioning pipeline: pulls a fixed list of secrets from one HashiCorp Vault KV
/// secrets engine, encrypts each with an IPipelineDataProtector as soon as it is read, and writes
/// them out as one file per secret - the folder layout <see cref="FilePerSecretCache"/> reads at
/// runtime. It is independent of HkdfGuard.Cache.HashiCorpVault's runtime cache, and of any key
/// ring. Naming, encrypting, keeping and writing are <see cref="SecretPipelineWriter"/>'s.
/// <code>
/// using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
/// using var token = new StaticVaultTokenSource(vaultToken);
/// using var writer = new HashiCorpVaultSecretPipelineWriter(address, token, protector,
///     ["myapp/db#username", "myapp/db#password", "myapp/api"]);
/// await writer.PullSecretsAsync();
/// writer.WriteProtectedSecretFiles(@"C:\HkdfGuardSecrets\myapp");
/// // Then hand protector.GetKeyAsBase64() to the wrap tool, and register the key at version 3.
/// </code>
/// <para>
/// A secret name is a path within the engine, with the key to read after '#': "myapp/db#password"
/// reads the password key of the secret at myapp/db, and "myapp/db" reads its
/// <see cref="HashiCorpVaultPipelineOptions.DefaultKey"/> (written as myapp__db__password and
/// myapp__db). A string is read as its text; a number, true or false as its JSON text.
/// </para>
/// <para>
/// Vault's response is read into pinned memory, and every buffer holding a value is zeroed. The
/// Vault token comes from an IVaultTokenSource, in plaintext, copied into pinned memory for each
/// read and zeroed once it has been sent. A request that fails transiently is retried as
/// <see cref="HashiCorpVaultPipelineOptions"/> says; any other failure propagates. For mutual TLS,
/// give <see cref="HashiCorpVaultPipelineOptions.Tls"/> a PEM certificate and key: a
/// password-protected PKCS#12 key store needs a protector on a key ring.
/// </para>
/// </summary>
public sealed class HashiCorpVaultSecretPipelineWriter : SecretPipelineWriter
{
    /// <summary>The longest secret path read.</summary>
    public const int MaxSecretNameLength = 512;

    private readonly HttpClient _http;
    private readonly IVaultTokenSource _tokenSource;
    private readonly TimeSpan _timeout;
    private readonly int _retryCount;
    private readonly TimeSpan _retryDelay;
    private readonly string? _namespace;
    private readonly string _readPrefix;
    private readonly string[] _dataPath;

    /// <param name="address">Vault's address, e.g. https://vault.example.com:8200 - the same value
    /// as VAULT_ADDR. Must be https, except on a loopback address.</param>
    /// <param name="tokenSource">Supplies the token every read is made with. Owned by the caller:
    /// the writer never disposes it.</param>
    /// <param name="protector">Encrypts every value read. Owned by the caller: the writer never
    /// disposes it.</param>
    /// <param name="secretNames">The secrets to pull, each a path with the key to read after '#' if
    /// any. Copied: a later change to the list isn't seen.</param>
    /// <param name="options">The KV engine read and how to reach it; null for KV version 2 at
    /// "secret", reading the key "value".</param>
    /// <exception cref="ArgumentNullException">address, tokenSource, protector or secretNames is null</exception>
    /// <exception cref="ArgumentException">secretNames is empty, or holds a null, a name that isn't a
    /// path (with a key), one whose file name isn't one FilePerSecretCache can read, or two with the
    /// same file name, in any case; or the options are invalid: a mount path, default key or namespace
    /// that isn't one, an HttpMessageHandler that follows redirects without AllowRedirects, or TLS options
    /// that can't be read</exception>
    /// <exception cref="ArgumentOutOfRangeException">The KV version isn't one, or the timeout isn't positive</exception>
    public HashiCorpVaultSecretPipelineWriter(Uri address, IVaultTokenSource tokenSource, IPipelineDataProtector protector,
        IList<string> secretNames, HashiCorpVaultPipelineOptions? options = null)
        : base(protector, secretNames, IsValidSecretName, (options ?? new HashiCorpVaultPipelineOptions()).DefaultKey)
    {
        ArgumentNullException.ThrowIfNull(tokenSource);
        options ??= new HashiCorpVaultPipelineOptions();
        var apiBase = VaultHttp.ApiBase(address);

        VaultHttp.CheckSettings(options.MountPath, options.Namespace, options.Timeout, options.RetryCount, options.RetryDelay, nameof(options));
        if (!Enum.IsDefined(options.KvVersion))
            throw new ArgumentOutOfRangeException(nameof(options), options.KvVersion, "The KV version must be V1 or V2.");
        VaultHttp.CheckRedirects(options.HttpMessageHandler, options.AllowRedirects, nameof(options));

        _tokenSource = tokenSource;
        _timeout = options.Timeout;
        _retryCount = options.RetryCount;
        _retryDelay = options.RetryDelay;
        _namespace = options.Namespace;
        (_readPrefix, _dataPath) = options.KvVersion == VaultKvVersion.V2
            ? ($"{options.MountPath}/data/", new[] { "data", "data" })
            : ($"{options.MountPath}/", new[] { "data" });

        // Follows no redirects: one would carry X-Vault-Token wherever it points.
        _http = VaultHttp.CreateHttpClient(apiBase, options.HttpMessageHandler, options.Tls);
    }

    /// <summary>Whether path is a secret's path: at most <see cref="MaxSecretNameLength"/> characters, as Vault takes it.</summary>
    public static bool IsValidSecretName(string path) => path.Length <= MaxSecretNameLength && VaultHttp.IsValidPath(path);

    /// <summary>Releases the writer's connections, and its HTTP handler unless the caller supplied it.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _http.Dispose();
    }

    /// <inheritdoc/>
    /// <exception cref="HttpRequestException">Vault refused the read, or couldn't be reached</exception>
    /// <exception cref="InvalidDataException">The response isn't Vault's JSON, or holds a key twice</exception>
    /// <exception cref="InvalidOperationException">The token source supplied no token</exception>
    protected override async Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        // Pinned, and zeroed once the read is done. Asked for once per secret; a source's failure is
        // its own to retry, so isn't retried here.
        var token = ArrayUtility.AllocatePinned<char>(VaultHttp.MaxTokenLength);
        try
        {
            int tokenLength;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                tokenLength = await _tokenSource.CopyTokenAsync(token, timeout.Token).ConfigureAwait(false);
            }

            if (tokenLength is <= 0 or > VaultHttp.MaxTokenLength || !VaultHttp.IsValidToken(token.AsSpan(0, tokenLength)))
                throw new InvalidOperationException("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.");

            // An attempt encrypts nothing until it has read the whole body, so a failed one hands nothing over.
            var read = await VaultHttp.WithRetriesAsync(_retryCount, _retryDelay,
                attempt => ReadAsync(name, token.AsMemory(0, tokenLength), requests, attempt), cancellationToken).ConfigureAwait(false);
            foreach (var (fileName, value) in read)
                values.Add(fileName, value);
        }
        finally
        {
            ArrayUtility.ZeroMemory(token.AsSpan());
        }
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout.
    private async Task<Dictionary<string, string>> ReadAsync(string path, ReadOnlyMemory<char> token, IReadOnlyList<SecretRequest> requests,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);

        using var request = VaultHttp.CreateRequest(HttpMethod.Get, new Uri(_readPrefix + path, UriKind.Relative), _namespace);

        // Sent unbuffered, and the header's copy of the token zeroed once it has gone.
        using var response = await VaultHttp.SendWithTokenAsync(_http, request, token, timeout.Token).ConfigureAwait(false);
        await using var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            var (buffer, length) = await PinnedBody.ReadAsync(body, timeout.Token).ConfigureAwait(false);
            try
            {
                return ProtectValues(buffer.AsSpan(0, length), requests);
            }
            finally
            {
                ArrayUtility.ZeroMemory(buffer);
            }
        }

        // An error response holds no secret: read as Vault's error list, up to a bound.
        var errors = await VaultHttp.ReadErrorsAsync(body, timeout.Token).ConfigureAwait(false);

        // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        // secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        // (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if (response.StatusCode == HttpStatusCode.NotFound && errors is { Length: 0 })
            return [];

        var detail = errors is { Length: > 0 } ? ": " + string.Join("; ", errors) : "";
        throw new HttpRequestException($"Vault refused to read '{path}': {(int)response.StatusCode} {response.StatusCode}{detail}",
            null, response.StatusCode);
    }

    // Encrypts the value of each requested key in the secret's data object, by file name.
    private Dictionary<string, string> ProtectValues(ReadOnlySpan<byte> json, IReadOnlyList<SecretRequest> requests)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var reader = new Utf8JsonReader(json);
        try
        {
            if (!StartsObject(ref reader))
                throw new InvalidDataException("Vault's response isn't a JSON object.");
            if (MoveToObject(ref reader, _dataPath))
                ProtectKeys(ref reader, requests, values);

            return values;
        }
        catch (JsonException e)
        {
            // Not chained: the reader's message quotes the byte it rejected, which may be in the secret.
            throw new InvalidDataException($"Vault's response isn't valid JSON (at byte {e.BytePositionInLine} of line {e.LineNumber}).");
        }
    }

    // Leaves reader at the start of the object path leads to; false if it leads to none.
    private static bool MoveToObject(ref Utf8JsonReader reader, string[] path)
    {
        foreach (var name in path)
        {
            var found = false;
            while (!found && NextProperty(ref reader))
            {
                var isNext = reader.ValueTextEquals(name);
                reader.Read();
                if (isNext && reader.TokenType == JsonTokenType.StartObject)
                    found = true;
                else
                    reader.Skip();
            }

            if (!found)
                return false;
        }

        return true;
    }
}
