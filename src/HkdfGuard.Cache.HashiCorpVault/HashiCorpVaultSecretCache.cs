using System.Buffers;
using System.Net;
using System.Text.Json;
using HkdfGuard.Abstractions;
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
/// failure propagates as it is.
/// </para>
/// <para>
/// Authentication isn't the cache's: every fetch asks its <see cref="IVaultTokenProvider"/> for a
/// token, so a provider can log in, renew and replace tokens however it likes. Requests go to /v1/
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
/// decryption, socket reads). The token, unavoidably, is a string. Dispose the cache to release its
/// connections.
/// </para>
/// </summary>
public sealed class HashiCorpVaultSecretCache : RemoteSecretCache, IDisposable
{
    /// <summary>The longest secret path looked up.</summary>
    public const int MaxSecretNameLength = 512;

    private static readonly SearchValues<char> SegmentCharacters =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.");

    private readonly HttpClient _http;
    private readonly IVaultTokenProvider _tokenProvider;
    private readonly TimeSpan _timeout;
    private readonly string? _namespace;
    private readonly string _readPrefix;
    private readonly string[] _dataPath;
    private readonly string _defaultKey;

    /// <param name="address">Vault's address, e.g. https://vault.example.com:8200 - the same value
    /// as VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server).
    /// A path, if any, is kept as a prefix (Vault behind a reverse proxy).</param>
    /// <param name="tokenProvider">Supplies the token every read is made with.</param>
    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="options">The KV engine read and how to reach it; null for KV version 2 at
    /// "secret", reading the key "value".</param>
    /// <param name="logger">Optional; see RemoteSecretCache.</param>
    /// <exception cref="ArgumentNullException">address, tokenProvider or keyRing is null</exception>
    /// <exception cref="ArgumentException">address isn't https (or http on loopback), or holds
    /// credentials, a query or a fragment; or the mount path, default key or namespace isn't one; or
    /// the HttpMessageHandler follows redirects without AllowRedirects</exception>
    /// <exception cref="ArgumentOutOfRangeException">The KV version isn't one, or the timeout isn't positive</exception>
    public HashiCorpVaultSecretCache(Uri address, IVaultTokenProvider tokenProvider, IKeyRing keyRing,
        HashiCorpVaultSecretCacheOptions? options = null, ILogger<HashiCorpVaultSecretCache>? logger = null)
        : base(keyRing, SecretNameMatching.Exact, logger)
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);
        options ??= new HashiCorpVaultSecretCacheOptions();
        var apiBase = ApiBase(address);

        if (!IsValidPath(options.MountPath))
            throw new ArgumentException($"The mount path '{options.MountPath}' isn't a Vault path.", nameof(options));
        if (!IsValidKey(options.DefaultKey))
            throw new ArgumentException($"The default key '{options.DefaultKey}' isn't a key: 1-{MaxKeyLength} printable ASCII characters other than space, '!' and '#'.", nameof(options));
        if (options.Namespace is not null && !IsValidPath(options.Namespace))
            throw new ArgumentException($"The namespace '{options.Namespace}' isn't a Vault path.", nameof(options));
        if (!Enum.IsDefined(options.KvVersion))
            throw new ArgumentOutOfRangeException(nameof(options), options.KvVersion, "The KV version must be V1 or V2.");
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.Timeout, TimeSpan.Zero, nameof(options));
        if (options.HttpMessageHandler is { } supplied && !options.AllowRedirects && FollowsRedirects(supplied))
            throw new ArgumentException(
                "The HttpMessageHandler follows redirects, which would send the Vault token wherever they point. Set its AllowAutoRedirect to false, or set AllowRedirects if every redirect target may see the token.",
                nameof(options));

        _tokenProvider = tokenProvider;
        _timeout = options.Timeout;
        _namespace = options.Namespace;
        _defaultKey = options.DefaultKey;
        (_readPrefix, _dataPath) = options.KvVersion == VaultKvVersion.V2
            ? ($"{options.MountPath}/data/", new[] { "data", "data" })
            : ($"{options.MountPath}/", new[] { "data" });

        var handler = options.HttpMessageHandler ?? new SocketsHttpHandler
        {
            // A redirect would carry X-Vault-Token to wherever it points: HttpClient drops only the
            // Authorization header when following one. Vault's standbys forward requests to the
            // active node themselves, so a redirect is answered as an error instead.
            AllowAutoRedirect = false,
            UseCookies = false,
            // Picks up a changed DNS record (a failover) without restarting.
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        _http = new HttpClient(handler, disposeHandler: options.HttpMessageHandler is null)
        {
            BaseAddress = apiBase,
            // The fetch's own timeout covers the token as well as the request.
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    /// <summary>
    /// Whether name is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
    /// '.', no segment "." or "..", at most <see cref="MaxSecretNameLength"/> characters. A key to
    /// read follows it in a lookup, after '#' (see <see cref="RemoteSecretCache.IsValidKey"/>).
    /// </summary>
    public static bool IsValidSecretName(string? name)
        => !string.IsNullOrEmpty(name) && name.Length <= MaxSecretNameLength && IsValidPath(name);

    /// <summary>Whether token can go in a header: non-empty printable ASCII, with no spaces.</summary>
    internal static bool IsValidToken(string? token)
        => !string.IsNullOrEmpty(token) && token.All(c => c is > ' ' and <= '~');

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
        var path = name;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        var token = await _tokenProvider.GetTokenAsync(timeout.Token).ConfigureAwait(false);
        if (!IsValidToken(token))
            throw new InvalidOperationException("The Vault token provider returned no token, or one that isn't printable ASCII without spaces.");

        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_readPrefix + path, UriKind.Relative));
        request.Headers.Add("X-Vault-Request", "true");
        request.Headers.Add("X-Vault-Token", token);
        if (_namespace is not null)
            request.Headers.Add("X-Vault-Namespace", _namespace);

        // Unbuffered: HttpClient would otherwise copy the body into a pooled buffer it returns uncleared.
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        await using var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            await SecretJsonBody.CaptureKeysAsync(body, value, _dataPath, timeout.Token).ConfigureAwait(false);
            return;
        }

        var errors = await ReadErrorsAsync(body, timeout.Token).ConfigureAwait(false);

        // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        // secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        // (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if (response.StatusCode == HttpStatusCode.NotFound && errors is { Length: 0 })
            return;

        var detail = errors is { Length: > 0 } ? ": " + string.Join("; ", errors) : "";
        throw new HttpRequestException($"Vault refused to read '{path}': {(int)response.StatusCode} {response.StatusCode}{detail}",
            null, response.StatusCode);
    }

    // The errors Vault listed in an error response; null if it isn't Vault's JSON.
    private static async Task<string[]?> ReadErrorsAsync(Stream body, CancellationToken cancellationToken)
    {
        try
        {
            using var json = await JsonDocument.ParseAsync(body, cancellationToken: cancellationToken).ConfigureAwait(false);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            if (!root.TryGetProperty("errors", out var errors))
                return [];

            return errors.ValueKind == JsonValueKind.Array ? errors.EnumerateArray().Select(e => e.ToString()).ToArray() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // /v1/ under Vault's address, refusing an address that would send tokens in the clear (http
    // anywhere but loopback) or that carries credentials, a query or a fragment.
    private static Uri ApiBase(Uri address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.IsAbsoluteUri)
            throw new ArgumentException($"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.", nameof(address));
        if (address.Scheme != Uri.UriSchemeHttps && !(address.Scheme == Uri.UriSchemeHttp && address.IsLoopback))
            throw new ArgumentException(
                $"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token.", nameof(address));
        if (address.UserInfo.Length > 0 || address.Query.Length > 0 || address.Fragment.Length > 0)
            throw new ArgumentException($"Vault's address '{address}' must not hold credentials, a query or a fragment.", nameof(address));

        return new Uri(address.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/v1/");
    }

    // Whether the handler at the bottom of handler's DelegatingHandler chain follows redirects. One
    // of a type other than SocketsHttpHandler or HttpClientHandler can't be told, so counts as not.
    private static bool FollowsRedirects(HttpMessageHandler handler)
    {
        while (handler is DelegatingHandler { InnerHandler: { } inner })
            handler = inner;

        return handler switch
        {
            SocketsHttpHandler sockets => sockets.AllowAutoRedirect,
            HttpClientHandler client => client.AllowAutoRedirect,
            _ => false,
        };
    }

    // '/'-separated segments, none empty, "." or "..": a path that stays where it's put.
    private static bool IsValidPath(ReadOnlySpan<char> path)
    {
        foreach (var range in path.Split('/'))
        {
            if (!IsValidSegment(path[range]))
                return false;
        }

        return true;
    }

    private static bool IsValidSegment(ReadOnlySpan<char> segment)
        => !segment.IsEmpty && segment is not "." and not ".." && !segment.ContainsAnyExcept(SegmentCharacters);
}
