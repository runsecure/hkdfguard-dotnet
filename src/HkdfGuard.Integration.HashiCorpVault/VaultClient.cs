using System.Globalization;
using System.Net;
using System.Net.Sockets;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// A HashiCorp Vault client: a port of vault-client-go. Generic <see cref="ReadAsync"/>,
/// <see cref="WriteAsync"/>, <see cref="ListAsync"/> and <see cref="DeleteAsync"/> reach any path; the
/// methods generated from Vault's OpenAPI spec reach every known endpoint, typed, grouped as
/// <see cref="Auth"/>, <see cref="Identity"/>, <see cref="Secrets"/> and <see cref="System"/>.
/// <para>
/// Tokens are held only protected - encrypted by the client's token protector, a protector on a key
/// ring (keyRing.CreateProtector(<see cref="TokenPurpose"/>)) - and supplied by an
/// <see cref="IVaultTokenProvider"/>. A token is decrypted only as a request is sent, into stack or
/// pinned memory and from there into the one string its header needs, which is zeroed as soon as the
/// request has gone. A token Vault returns (a login's, a wrapping token) is protected as the response
/// is read, so never becomes a string either. Request and response bodies are held in pinned memory
/// that is zeroed after use; what a generated model holds, though, is ordinary strings.
/// </para>
/// <para>
/// Defaults are stricter than vault-client-go's: Vault's address must be https except on loopback (or
/// a unix socket), and redirects - which would carry the token wherever they point - fail with
/// <see cref="VaultRedirectException"/> unless <see cref="VaultClientOptions.FollowRedirects"/> is set.
/// Failures are retried as vault-client-go retries them (<see cref="VaultRetryOptions"/>). Vault's
/// refusals fail with <see cref="VaultResponseException"/>; a request that outlives
/// <see cref="VaultClientOptions.RequestTimeout"/> fails with TimeoutException.
/// </para>
/// <para>
/// Thread-safe. Settings changed with the Set and Clear methods apply to requests started afterwards.
/// Dispose the client to release its connections.
/// </para>
/// </summary>
public sealed partial class VaultClient : IDisposable
{
    /// <summary>
    /// The purpose to create the token protector with - keyRing.CreateProtector(TokenPurpose) - so a
    /// token protected for the client can't be decrypted as anything else, nor anything else as it.
    /// </summary>
    public const string TokenPurpose = "HkdfGuard.Integration.HashiCorpVault.Token";

    private readonly VaultClientOptions _options;
    private readonly IDataProtector _tokenProtector;
    private readonly ILogger? _logger;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _baseAddress;
    private readonly Func<HttpResponseMessage?, Exception?, bool> _checkRetry;
    private readonly Func<TimeSpan, TimeSpan, int, HttpResponseMessage?, TimeSpan> _backoff;
    private readonly ReplicationStateCache? _replicationStates;
    private readonly Lock _modifiersLock = new();
    private RequestModifiers _modifiers;

    /// <param name="tokenProtector">Protects and decrypts tokens: a protector on the key ring,
    /// keyRing.CreateProtector(<see cref="TokenPurpose"/>). Every token the client is given must be
    /// protected by it.</param>
    /// <param name="options">How to reach Vault; null for the defaults (https://127.0.0.1:8200).
    /// Copied: changing them afterwards changes nothing.</param>
    /// <param name="logger">Optional: retries and followed redirects are logged.</param>
    /// <exception cref="ArgumentNullException">tokenProtector is null</exception>
    /// <exception cref="ArgumentException">The address isn't https (or http on loopback, or unix), or
    /// holds credentials, a query or a fragment; the namespace can't be sent; the HttpMessageHandler
    /// follows redirects, or isn't a SocketsHttpHandler when TLS options or a unix address need one; or
    /// a certificate can't be read</exception>
    /// <exception cref="ArgumentOutOfRangeException">The request timeout or a retry wait is negative</exception>
    public VaultClient(IDataProtector tokenProtector, VaultClientOptions? options = null, ILogger<VaultClient>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(tokenProtector);
        options = (options ?? new VaultClientOptions()).Clone();
        _baseAddress = BaseAddress(options);
        if (options.RequestTimeout < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), options.RequestTimeout, "The request timeout must not be negative.");
        if (options.Retry.RetryWaitMin < TimeSpan.Zero || options.Retry.RetryWaitMax < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), "The retry waits must not be negative.");
        if (!string.IsNullOrEmpty(options.Namespace) && !IsValidNamespace(options.Namespace))
            throw new ArgumentException($"The namespace '{options.Namespace}' contains non-printable characters.", nameof(options));
        if (options.HttpMessageHandler is { } supplied && VaultHttp.FollowsRedirects(supplied))
            throw new ArgumentException(
                "The HttpMessageHandler follows redirects, which would send the Vault token wherever they point. Set its AllowAutoRedirect to false: the client follows redirects itself when FollowRedirects is set.",
                nameof(options));

        var handler = options.HttpMessageHandler ?? VaultHttp.CreateHandler();
        try
        {
            Configure(handler, options);
        }
        catch when (options.HttpMessageHandler is null)
        {
            handler.Dispose();
            throw;
        }

        _options = options;
        _tokenProtector = tokenProtector;
        _logger = logger;
        _checkRetry = options.Retry.CheckRetry ?? VaultRetryOptions.DefaultRetryPolicy;
        _backoff = options.Retry.Backoff ?? VaultRetryOptions.LinearJitterBackoff;
        _http = new HttpClient(handler, disposeHandler: options.HttpMessageHandler is null)
        {
            // The client's own timeout covers the token, retries and redirect as well as the request.
            Timeout = Timeout.InfiniteTimeSpan,
        };
        _ownsHttp = true;
        _replicationStates = options.EnforceReadYourWritesConsistency ? new ReplicationStateCache() : null;
        _modifiers = new RequestModifiers
        {
            UserAgent = VaultUserAgent.Value,
            Token = options.Token,
            Namespace = string.IsNullOrEmpty(options.Namespace) ? null : options.Namespace,
        };
    }

    // A clone: the same connections, a copy of the settings and replication states.
    private VaultClient(VaultClient original)
    {
        _options = original._options;
        _tokenProtector = original._tokenProtector;
        _logger = original._logger;
        _http = original._http;
        _ownsHttp = false;
        _baseAddress = original._baseAddress;
        _checkRetry = original._checkRetry;
        _backoff = original._backoff;
        _replicationStates = original._replicationStates?.Clone();
        _modifiers = Volatile.Read(ref original._modifiers);
    }

    /// <summary>A copy of the options the client was created with.</summary>
    public VaultClientOptions Options => _options.Clone();

    /// <summary>
    /// A client with this one's options, settings (token, namespace, headers, callbacks...) and
    /// replication states, which then change independently. It shares this client's connections:
    /// disposing it does nothing, and it can't be used once this client is disposed.
    /// </summary>
    public VaultClient Clone() => new(this);

    /// <summary>Releases the client's connections, and its HTTP handler unless the options supplied it. A clone's does nothing.</summary>
    public void Dispose()
    {
        if (_ownsHttp)
            _http.Dispose();
    }

    /// <summary>
    /// token, protected by the client's token protector: for <see cref="SetToken(IVaultTokenProvider)"/>
    /// or <see cref="VaultRequestOptions.Token"/>. token is read-only, so it isn't zeroed: clear it once
    /// this returns.
    /// </summary>
    /// <exception cref="ArgumentException">token is empty, or isn't printable ASCII without spaces</exception>
    public StaticVaultToken ProtectToken(ReadOnlySpan<char> token) => StaticVaultToken.Protect(_tokenProtector, token);

    /// <summary>Makes every later request with token, unless the request sets its own; see https://developer.hashicorp.com/vault/docs/concepts/tokens.</summary>
    public void SetToken(IVaultTokenProvider token)
    {
        ArgumentNullException.ThrowIfNull(token);
        Update(m => m with { Token = token });
    }

    /// <summary>Protects token and makes every later request with it; see <see cref="ProtectToken"/>.</summary>
    /// <exception cref="ArgumentException">token is empty, or isn't printable ASCII without spaces</exception>
    public void SetToken(ReadOnlySpan<char> token) => SetToken(ProtectToken(token));

    /// <summary>Makes later requests without a token, unless they set their own.</summary>
    public void ClearToken() => Update(m => m with { Token = null });

    /// <summary>Makes every later request in ns, unless the request sets its own; empty for none. See https://developer.hashicorp.com/vault/docs/enterprise/namespaces.</summary>
    /// <exception cref="ArgumentException">ns contains non-printable characters</exception>
    public void SetNamespace(string ns)
    {
        ArgumentNullException.ThrowIfNull(ns);
        if (ns.Length > 0 && !IsValidNamespace(ns))
            throw new ArgumentException($"The namespace '{ns}' contains non-printable characters.", nameof(ns));
        Update(m => m with { Namespace = ns.Length > 0 ? ns : null });
    }

    /// <summary>Makes later requests in no namespace, unless they set their own.</summary>
    public void ClearNamespace() => Update(m => m with { Namespace = null });

    /// <summary>Sends credentials (X-Vault-MFA) with every later request; see https://developer.hashicorp.com/vault/docs/auth/login-mfa.</summary>
    /// <exception cref="ArgumentException">A credential is empty or not printable ASCII</exception>
    public void SetMfaCredentials(params string[] credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        string[] copy = [.. credentials];
        RequestModifiers.ValidateMfaCredentials(copy);
        Update(m => m with { MfaCredentials = copy });
    }

    /// <summary>Stops sending MFA credentials.</summary>
    public void ClearMfaCredentials() => Update(m => m with { MfaCredentials = [] });

    /// <summary>
    /// Asks Vault to wrap every later response for ttl (X-Vault-Wrap-TTL); zero to stop. See
    /// https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
    /// </summary>
    public void SetResponseWrapping(TimeSpan ttl)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(ttl, TimeSpan.Zero);
        Update(m => m with { ResponseWrappingTtl = ttl });
    }

    /// <summary>Stops asking Vault to wrap responses.</summary>
    public void ClearResponseWrapping() => Update(m => m with { ResponseWrappingTtl = TimeSpan.Zero });

    /// <summary>Adds headers to every later request, replacing those set before; names starting X-Vault- are refused.</summary>
    /// <exception cref="ArgumentException">A header has no name, or is named X-Vault-*</exception>
    public void SetCustomHeaders(IReadOnlyDictionary<string, IReadOnlyList<string>> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        RequestModifiers.ValidateCustomHeaders(headers);
        var copy = headers.ToDictionary(h => h.Key, IReadOnlyList<string> (h) => [.. h.Value], StringComparer.OrdinalIgnoreCase);
        Update(m => m with { CustomHeaders = copy });
    }

    /// <summary>Stops adding custom headers.</summary>
    public void ClearCustomHeaders() => Update(m => m with { CustomHeaders = new Dictionary<string, IReadOnlyList<string>>() });

    /// <summary>Calls callbacks with each attempt's request before it's sent (without its token), replacing those set before.</summary>
    public void SetRequestCallbacks(params Action<HttpRequestMessage>[] callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        Action<HttpRequestMessage>[] copy = [.. callbacks];
        Update(m => m with { RequestCallbacks = copy });
    }

    /// <summary>Stops calling request callbacks.</summary>
    public void ClearRequestCallbacks() => Update(m => m with { RequestCallbacks = [] });

    /// <summary>Calls callbacks with each request and its response once Vault has answered, replacing those set before.</summary>
    public void SetResponseCallbacks(params Action<HttpRequestMessage, HttpResponseMessage>[] callbacks)
    {
        ArgumentNullException.ThrowIfNull(callbacks);
        Action<HttpRequestMessage, HttpResponseMessage>[] copy = [.. callbacks];
        Update(m => m with { ResponseCallbacks = copy });
    }

    /// <summary>Stops calling response callbacks.</summary>
    public void ClearResponseCallbacks() => Update(m => m with { ResponseCallbacks = [] });

    /// <summary>
    /// Sends a forwarding header with every later request (Vault Enterprise): X-Vault-Forward for
    /// Always, X-Vault-Inconsistent for Inconsistent, none for None. See
    /// https://developer.hashicorp.com/vault/docs/enterprise/consistency#vault-1-7-mitigations.
    /// </summary>
    public void SetReplicationForwardingMode(ReplicationForwardingMode mode)
    {
        if (!Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "Not a forwarding mode.");
        Update(m => m with { ReplicationForwardingMode = mode });
    }

    /// <summary>Stops sending a forwarding header.</summary>
    public void ClearReplicationForwardingMode() => Update(m => m with { ReplicationForwardingMode = ReplicationForwardingMode.None });

    /// <summary>
    /// Whether exception - or the first <see cref="VaultResponseException"/> or
    /// <see cref="VaultRedirectException"/> among its inner exceptions - is Vault answering with status.
    /// </summary>
    public static bool IsErrorStatus(Exception? exception, HttpStatusCode status)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e is VaultResponseException or VaultRedirectException)
                return ((HttpRequestException)e).StatusCode == status;
        }

        return false;
    }

    /// <summary>Whether value can go in a header: printable ASCII, spaces allowed.</summary>
    internal static bool IsValidNamespace(ReadOnlySpan<char> value)
        => !value.ContainsAnyExceptInRange(' ', '~');

    // For the generated methods: options' mount path, or the endpoint's default.
    internal static string MountPathOr(VaultRequestOptions? options, string defaultMountPath)
        => options?.MountPath?.Trim('/') is { Length: > 0 } mountPath ? mountPath : defaultMountPath;

    // For the generated methods: value as one path segment, '/' included.
    internal static string EscapePathSegment(string value) => Uri.EscapeDataString(value);

    // For the generated methods: options' query parameters, to add the endpoint's own to.
    internal static List<KeyValuePair<string, string>> QueryParameters(VaultRequestOptions? options)
        => options?.QueryParameters is { } parameters ? [.. parameters] : [];

    internal static string FormatQueryValue(string value) => value;

    internal static string FormatQueryValue(bool value) => value ? "true" : "false";

    internal static string FormatQueryValue(int value) => value.ToString(CultureInfo.InvariantCulture);

    internal static string FormatQueryValue(long value) => value.ToString(CultureInfo.InvariantCulture);

    private void Update(Func<RequestModifiers, RequestModifiers> change)
    {
        lock (_modifiersLock)
            _modifiers = change(_modifiers);
    }

    // scheme://host[:port][/prefix] with no trailing '/', to put /v1/... after; http://localhost for a
    // unix socket. Refuses an address that would send tokens in the clear (http anywhere but loopback,
    // unless allowed) or that carries credentials, a query or a fragment.
    private static string BaseAddress(VaultClientOptions options)
    {
        var address = options.Address ?? throw new ArgumentException("Vault's address is required.", nameof(options));
        if (!address.IsAbsoluteUri)
            throw new ArgumentException($"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.", nameof(options));

        if (address.Scheme == "unix")
        {
            if (UnixSocketPath(address).Trim('/').Length == 0)
                throw new ArgumentException($"Vault's address '{address}' names no socket, e.g. unix:///var/run/vault.sock.", nameof(options));
            return "http://localhost";
        }

        if (address.Scheme != Uri.UriSchemeHttps
            && !(address.Scheme == Uri.UriSchemeHttp && (address.IsLoopback || options.AllowUnencryptedHttp)))
            throw new ArgumentException(
                $"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), or with AllowUnencryptedHttp, since every request carries a token.",
                nameof(options));
        if (address.UserInfo.Length > 0 || address.Query.Length > 0 || address.Fragment.Length > 0)
            throw new ArgumentException($"Vault's address '{address}' must not hold credentials, a query or a fragment.", nameof(options));

        return address.GetLeftPart(UriPartial.Path).TrimEnd('/');
    }

    private static string UnixSocketPath(Uri address) => Uri.UnescapeDataString(address.AbsolutePath);

    // A unix address and TLS options configure the SocketsHttpHandler at the bottom of handler's chain.
    private static void Configure(HttpMessageHandler handler, VaultClientOptions options)
    {
        var unix = options.Address.Scheme == "unix";
        if (!unix && options.Tls.IsEmpty)
            return;

        var innermost = handler;
        while (innermost is DelegatingHandler { InnerHandler: { } inner })
            innermost = inner;
        if (innermost is not SocketsHttpHandler sockets)
            throw new ArgumentException(
                $"The HttpMessageHandler ({innermost.GetType()}) isn't a SocketsHttpHandler, so can't be given {(unix ? "a unix socket address" : "TLS options")}.",
                nameof(options));

        if (unix)
        {
            var endPoint = new UnixDomainSocketEndPoint(UnixSocketPath(options.Address));
            sockets.ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            };
        }

        if (!options.Tls.IsEmpty)
            options.Tls.ApplyTo(sockets);
    }
}
