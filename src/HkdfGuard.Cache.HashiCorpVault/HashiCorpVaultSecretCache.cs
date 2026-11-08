using System.Net;
using HkdfGuard.Abstractions;
using HkdfGuard.Integration.HashiCorpVault;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.HashiCorpVault;

/// <summary>
/// An IProtectedReadOnlyCache over the secrets in one HashiCorp Vault KV secrets engine. The first
/// lookup of a name that isn't cached yet reads that one secret (GET on its path; for KV version 2,
/// its latest version); fetching, encryption, caching and telemetry are RemoteSecretCache's. This
/// class never lists secrets, so the token's policy needs only <c>read</c> on the paths it reads,
/// never <c>list</c>.
/// <para>
/// A name is a secret's path within the engine, with the key to read after '#':
/// "myapp/db#password" reads the password key of the secret at myapp/db, and "myapp/db" reads its
/// <see cref="HashiCorpVaultSecretCacheOptions.DefaultKey"/>. One read caches every key the secret
/// holds, so the first lookup of any of them reads the secret once and the rest are already cached
/// (see RemoteSecretCache). A string is cached as its UTF-8 bytes; a number, true or false as its
/// JSON text; a null, object or array value isn't cached. Paths are matched exactly, as Vault
/// matches them, and so are keys. A path that isn't one - segments of ASCII letters, digits, '-',
/// '_' and '.', no segment "." or "..", at most <see cref="MaxSecretNameLength"/> characters, such as
/// the configuration path "ConnectionStrings:Admin" - is reported missing without a call.
/// </para>
/// <para>
/// A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
/// deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
/// reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
/// path, a 404 naming an error such as a mount that doesn't exist, Vault sealed or unreachable)
/// propagates as an HttpRequestException carrying Vault's status and errors; a token provider's
/// failure propagates as it is. A request that fails transiently - no answer, a connection lost
/// mid-response, a timed-out attempt, 429 or a 5xx other than 501 - is first retried
/// <see cref="HashiCorpVaultSecretCacheOptions.RetryCount"/> times (3-10), waiting
/// <see cref="HashiCorpVaultSecretCacheOptions.RetryDelay"/> and doubling, up to 10 seconds, plus a
/// random 0-100 ms each time so clients reconnecting together spread out.
/// </para>
/// <para>
/// Authentication isn't the cache's: every fetch asks its <see cref="IVaultTokenProvider"/> for a
/// token, so a provider can log in, renew and replace tokens however it likes. The token is handed
/// over protected - encrypted by the cache's token protector, a protector on the key ring
/// (keyRing.CreateProtector(<see cref="TokenPurpose"/>)) - and a fetch given one that isn't fails
/// with InvalidOperationException. It is decrypted only as its request is built, into stack or
/// pinned memory, and from there into the one string the header needs, whose memory is zeroed as
/// soon as the request has been sent. Requests go to /v1/
/// under Vault's address, which must be https except on loopback; the cache's own HTTP handler
/// follows no redirects, which would carry the token elsewhere. A fetch is
/// asynchronous through DecryptAsync and GetMaxDecryptedLengthAsync; through Decrypt and
/// TryGetMaxDecryptedLength it blocks the calling thread (off any SynchronizationContext) until Vault
/// answers or <see cref="HashiCorpVaultSecretCacheOptions.Timeout"/> passes.
/// </para>
/// <para>
/// The secret never becomes a string. The response isn't buffered by HttpClient (whose pooled
/// buffer would be returned uncleared): its body is read off the network into pinned memory, and
/// the value is unescaped into pinned memory and encrypted from there (SecretJsonBody); every buffer
/// holding it is zeroed. What can't be zeroed is below HttpClient: the HTTP stack's own buffers (TLS
/// encryption and decryption, socket reads and writes), which also see the token. Dispose the cache
/// to release its connections.
/// </para>
/// </summary>
public sealed class HashiCorpVaultSecretCache : RemoteSecretCache, IDisposable
{
    /// <summary>The longest secret path looked up.</summary>
    public const int MaxSecretNameLength = 512;

    /// <summary>
    /// The purpose to create the token protector with - keyRing.CreateProtector(TokenPurpose) - so a
    /// token protected for the cache can't be decrypted as anything else, nor anything else as it.
    /// </summary>
    public const string TokenPurpose = "HkdfGuard.Cache.HashiCorpVault.Token";

    private readonly HttpClient _http;
    private readonly IVaultTokenProvider _tokenProvider;
    private readonly IDataProtector _tokenProtector;
    private readonly TimeSpan _timeout;
    private readonly int _retryCount;
    private readonly TimeSpan _retryDelay;
    private readonly string? _namespace;
    private readonly string _readPrefix;
    private readonly string[] _dataPath;
    private readonly string _defaultKey;

    /// <param name="address">Vault's address, e.g. https://vault.example.com:8200 - the same value
    /// as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server).
    /// A path, if any, is kept as a prefix (Vault behind a reverse proxy).</param>
    /// <param name="tokenProvider">Supplies the token every read is made with, protected by tokenProtector.</param>
    /// <param name="tokenProtector">Decrypts the token tokenProvider supplies: a protector on the key
    /// ring, keyRing.CreateProtector(<see cref="TokenPurpose"/>).</param>
    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="options">The KV engine read and how to reach it; null for KV version 2 at
    /// "secret", reading the key "value".</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">address, tokenProvider, tokenProtector or keyRing is null</exception>
    /// <exception cref="ArgumentException">address isn't https (or http on loopback), or holds
    /// credentials, a query or a fragment; the mount path, default key or namespace isn't one; the
    /// HttpMessageHandler follows redirects without AllowRedirects; or the TLS options can't be read,
    /// or are given with an HttpMessageHandler that isn't a SocketsHttpHandler</exception>
    /// <exception cref="ArgumentOutOfRangeException">The KV version isn't one, or the timeout isn't positive</exception>
    public HashiCorpVaultSecretCache(Uri address, IVaultTokenProvider tokenProvider, IDataProtector tokenProtector, IKeyRing keyRing,
        HashiCorpVaultSecretCacheOptions? options = null, ILogger<HashiCorpVaultSecretCache>? logger = null)
        : base(keyRing, SecretNameMatching.Exact, logger)
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);
        ArgumentNullException.ThrowIfNull(tokenProtector);
        options ??= new HashiCorpVaultSecretCacheOptions();
        var apiBase = VaultHttp.ApiBase(address);

        VaultHttp.CheckSettings(options.MountPath, options.Namespace, options.Timeout, options.RetryCount, options.RetryDelay, nameof(options));
        if (!IsValidKey(options.DefaultKey))
            throw new ArgumentException($"The default key '{options.DefaultKey}' isn't a key: 1-{MaxKeyLength} printable ASCII characters other than space, '!' and '#'.", nameof(options));
        if (!Enum.IsDefined(options.KvVersion))
            throw new ArgumentOutOfRangeException(nameof(options), options.KvVersion, "The KV version must be V1 or V2.");
        VaultHttp.CheckRedirects(options.HttpMessageHandler, options.AllowRedirects, nameof(options));

        _tokenProvider = tokenProvider;
        _tokenProtector = tokenProtector;
        _timeout = options.Timeout;
        _retryCount = options.RetryCount;
        _retryDelay = options.RetryDelay;
        _namespace = options.Namespace;
        _defaultKey = options.DefaultKey;
        (_readPrefix, _dataPath) = options.KvVersion == VaultKvVersion.V2
            ? ($"{options.MountPath}/data/", new[] { "data", "data" })
            : ($"{options.MountPath}/", new[] { "data" });

        // Follows no redirects: one would carry X-Vault-Token wherever it points. The fetch's own
        // timeout covers the token as well as the request.
        _http = VaultHttp.CreateHttpClient(apiBase, options.HttpMessageHandler, options.Tls);
    }

    /// <summary>
    /// Whether name is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
    /// '.', no segment "." or "..", at most <see cref="MaxSecretNameLength"/> characters. A key to
    /// read follows it in a lookup, after '#' (see <see cref="RemoteSecretCache.IsValidKey"/>).
    /// </summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name) && name.Length <= MaxSecretNameLength && VaultHttp.IsValidPath(name);

    /// <summary>Releases the cache's connections, and its HTTP handler unless the caller supplied it.</summary>
    public void Dispose() => _http.Dispose();

    /// <inheritdoc/>
    protected override string DefaultKey => _defaultKey;

    /// <inheritdoc/>
    protected override bool IsValidName(string name) => IsValidSecretName(name);

    /// <inheritdoc/>
    protected override void Fetch(string name, SecretValueSink value)
        // Off the caller's SynchronizationContext, so blocking on it can't deadlock.
        => Task.Run(() => FetchAsync(name, value, CancellationToken.None).AsTask()).GetAwaiter().GetResult();

    /// <inheritdoc/>
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        // Asked for once per fetch; a provider's failure is its own to retry, so isn't retried here.
        string protectedToken;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(_timeout);
            protectedToken = await _tokenProvider.GetTokenAsync(timeout.Token).ConfigureAwait(false);
        }

        // A failed attempt has handed nothing to value: the body is read whole before anything is
        // parsed out of it, and a parse failure isn't transient.
        await VaultHttp.WithRetriesAsync(_retryCount, _retryDelay, attempt => ReadAsync(name, protectedToken, value, attempt), cancellationToken)
            .ConfigureAwait(false);
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout.
    private async Task ReadAsync(string path, string protectedToken, SecretValueSink value, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);

        using var request = VaultHttp.CreateRequest(HttpMethod.Get, new Uri(_readPrefix + path, UriKind.Relative), _namespace);

        // Decrypted into pinned memory, sent unbuffered, and both copies zeroed once it has gone.
        using var response = await VaultHttp.SendWithTokenAsync(_http, request, _tokenProtector, protectedToken, timeout.Token).ConfigureAwait(false);
        await using var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            await SecretJsonBody.CaptureKeysAsync(body, value, _dataPath, timeout.Token).ConfigureAwait(false);
            return;
        }

        // An error response holds no secret: read as Vault's error list, up to a bound.
        var errors = await VaultHttp.ReadErrorsAsync(body, timeout.Token).ConfigureAwait(false);

        // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        // secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        // (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if (response.StatusCode == HttpStatusCode.NotFound && errors is { Length: 0 })
            return;

        var detail = errors is { Length: > 0 } ? ": " + string.Join("; ", errors) : "";
        throw new HttpRequestException($"Vault refused to read '{path}': {(int)response.StatusCode} {response.StatusCode}{detail}",
            null, response.StatusCode);
    }
}
