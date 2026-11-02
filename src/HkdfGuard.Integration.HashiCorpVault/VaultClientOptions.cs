using System.Globalization;
using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// How a <see cref="VaultClient"/> reaches Vault: vault-client-go's ClientConfiguration. The client
/// copies these when it's created, so changing them afterwards changes nothing.
/// </summary>
public sealed class VaultClientOptions
{
    /// <summary>The address used when none is set: a local Vault server or agent.</summary>
    public const string DefaultAddress = "https://127.0.0.1:8200";

    /// <summary>
    /// Vault's address, scheme://host:port - VAULT_ADDR. https; http only on a loopback address (a
    /// local agent or dev server) unless <see cref="AllowUnencryptedHttp"/> is set, since every request
    /// carries a token; or unix:///path/to/socket for a Unix domain socket. A path, if any, is kept as
    /// a prefix (Vault behind a reverse proxy).
    /// </summary>
    public Uri Address { get; set; } = new(DefaultAddress);

    /// <summary>
    /// Allows an http address that isn't loopback, and redirects to one. Off: the token would cross
    /// the network in the clear.
    /// </summary>
    public bool AllowUnencryptedHttp { get; set; }

    /// <summary>
    /// The handler requests go through; null for the client's own SocketsHttpHandler (TLS 1.2+, no
    /// automatic redirects, no cookies, connections recycled every 5 minutes), which it disposes. A
    /// supplied handler isn't disposed. It must not follow redirects itself - HttpClient would carry
    /// X-Vault-Token along - and <see cref="Tls"/> or a unix address need it to be a SocketsHttpHandler,
    /// which the client then configures.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; set; }

    /// <summary>
    /// How long each request may take, its retries and redirect included, unless the caller's
    /// cancellation comes first - VAULT_CLIENT_TIMEOUT. Zero for none. Not applied to
    /// <see cref="VaultClient.ReadRawAsync"/>. Default 60 seconds.
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Which certificates to trust and to present.</summary>
    public VaultTlsOptions Tls { get; set; } = new();

    /// <summary>When and how often a failed request is retried.</summary>
    public VaultRetryOptions Retry { get; set; } = new();

    /// <summary>
    /// Limits how often requests are sent - VAULT_RATE_LIMIT. Null for no limit. One limiter can be
    /// shared by several clients.
    /// </summary>
    public VaultRateLimiter? RateLimiter { get; set; }

    /// <summary>
    /// Sends the replication states seen in earlier responses with every request, so a performance
    /// standby that hasn't caught up forwards it to the active node: read-your-writes consistency
    /// across a cluster, at a cost on every request. Requires Vault Enterprise; see
    /// https://developer.hashicorp.com/vault/docs/enterprise/consistency#vault-1-7-mitigations.
    /// </summary>
    public bool EnforceReadYourWritesConsistency { get; set; }

    /// <summary>
    /// Follows one redirect (301, 302 or 307) per request, never from https to http. Off: a redirect
    /// fails with <see cref="VaultRedirectException"/>, since it would carry the token wherever it
    /// points. Some calls need it - raft operations sent to a standby are redirected to the active node.
    /// </summary>
    public bool FollowRedirects { get; set; }

    /// <summary>
    /// The token every request is made with unless the request sets its own; null for none until
    /// <see cref="VaultClient.SetToken(IVaultTokenProvider)"/>.
    /// </summary>
    public IVaultTokenProvider? Token { get; set; }

    /// <summary>The namespace every request is made in unless the request sets its own - VAULT_NAMESPACE. Vault Enterprise.</summary>
    public string? Namespace { get; set; }

    /// <summary>
    /// Options from the environment variables vault-client-go reads, over the defaults:
    /// <list type="bullet">
    /// <item>VAULT_ADDR, VAULT_AGENT_ADDR - <see cref="Address"/> (VAULT_AGENT_ADDR wins if both are set)</item>
    /// <item>VAULT_CLIENT_TIMEOUT - <see cref="RequestTimeout"/>, a Go duration such as 30s</item>
    /// <item>VAULT_RATE_LIMIT - <see cref="RateLimiter"/>, rate[:burst] in requests per second</item>
    /// <item>VAULT_DISABLE_REDIRECTS - true turns <see cref="FollowRedirects"/> off; false leaves it as it is</item>
    /// <item>VAULT_TOKEN - <see cref="Token"/>, protected with tokenProtector; ignored without one</item>
    /// <item>VAULT_NAMESPACE - <see cref="Namespace"/></item>
    /// <item>VAULT_SKIP_VERIFY, VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH, VAULT_CLIENT_CERT,
    /// VAULT_CLIENT_KEY, VAULT_TLS_SERVER_NAME - <see cref="Tls"/></item>
    /// <item>VAULT_RETRY_WAIT_MIN, VAULT_RETRY_WAIT_MAX, VAULT_MAX_RETRIES - <see cref="Retry"/></item>
    /// </list>
    /// </summary>
    /// <param name="tokenProtector">The protector the client will be given, to protect VAULT_TOKEN
    /// with; null to ignore VAULT_TOKEN.</param>
    /// <exception cref="FormatException">A variable is set to a value that isn't one</exception>
    public static VaultClientOptions FromEnvironment(IDataProtector? tokenProtector = null)
        => FromEnvironment(Environment.GetEnvironmentVariable, tokenProtector);

    internal static VaultClientOptions FromEnvironment(Func<string, string?> variable, IDataProtector? tokenProtector)
    {
        var options = new VaultClientOptions();

        // Later variables win, as in vault-client-go.
        foreach (var name in (string[])["VAULT_ADDR", "VAULT_AGENT_ADDR"])
        {
            if (Value(variable, name) is { } address)
                options.Address = Parse(name, address, a => new Uri(a, UriKind.Absolute));
        }

        if (Value(variable, "VAULT_CLIENT_TIMEOUT") is { } timeout)
            options.RequestTimeout = Parse("VAULT_CLIENT_TIMEOUT", timeout, GoDuration.Parse);
        if (Value(variable, "VAULT_RATE_LIMIT") is { } rateLimit)
            options.RateLimiter = Parse("VAULT_RATE_LIMIT", rateLimit, ParseRateLimit);
        if (Value(variable, "VAULT_DISABLE_REDIRECTS") is { } disableRedirects && Parse("VAULT_DISABLE_REDIRECTS", disableRedirects, ParseBool))
            options.FollowRedirects = false;
        if (Value(variable, "VAULT_NAMESPACE") is { } ns)
        {
            if (!VaultClient.IsValidNamespace(ns))
                throw new FormatException("VAULT_NAMESPACE contains non-printable characters.");
            options.Namespace = ns;
        }

        if (tokenProtector is not null && Value(variable, "VAULT_TOKEN") is { } token)
        {
            if (!VaultHttp.IsValidToken(token))
                throw new FormatException("VAULT_TOKEN isn't a token: printable ASCII, with no spaces.");
            options.Token = StaticVaultToken.Protect(tokenProtector, token);
        }

        var tls = options.Tls;
        if (Value(variable, "VAULT_SKIP_VERIFY") is { } skipVerify)
            tls.InsecureSkipVerify = Parse("VAULT_SKIP_VERIFY", skipVerify, ParseBool);
        tls.ServerCertificateFile = Value(variable, "VAULT_CACERT") ?? tls.ServerCertificateFile;
        if (Value(variable, "VAULT_CACERT_BYTES") is { } caBytes)
            tls.ServerCertificatePem = Encoding.UTF8.GetBytes(caBytes);
        tls.ServerCertificateDirectory = Value(variable, "VAULT_CAPATH") ?? tls.ServerCertificateDirectory;
        tls.ClientCertificateFile = Value(variable, "VAULT_CLIENT_CERT") ?? tls.ClientCertificateFile;
        tls.ClientCertificateKeyFile = Value(variable, "VAULT_CLIENT_KEY") ?? tls.ClientCertificateKeyFile;
        tls.ServerName = Value(variable, "VAULT_TLS_SERVER_NAME") ?? tls.ServerName;

        var retry = options.Retry;
        if (Value(variable, "VAULT_RETRY_WAIT_MIN") is { } waitMin)
            retry.RetryWaitMin = Parse("VAULT_RETRY_WAIT_MIN", waitMin, GoDuration.Parse);
        if (Value(variable, "VAULT_RETRY_WAIT_MAX") is { } waitMax)
            retry.RetryWaitMax = Parse("VAULT_RETRY_WAIT_MAX", waitMax, GoDuration.Parse);
        if (Value(variable, "VAULT_MAX_RETRIES") is { } maxRetries)
            retry.RetryMax = Parse("VAULT_MAX_RETRIES", maxRetries, m => int.Parse(m, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture));

        return options;
    }

    /// <summary>A copy deep enough that changing it doesn't change this: its own Tls and Retry.</summary>
    internal VaultClientOptions Clone()
    {
        var clone = (VaultClientOptions)MemberwiseClone();
        clone.Tls = Tls.Clone();
        clone.Retry = Retry.Clone();
        return clone;
    }

    // An unset variable and an empty one are the same, as in vault-client-go.
    private static string? Value(Func<string, string?> variable, string name) => variable(name) is { Length: > 0 } value ? value : null;

    private static T Parse<T>(string name, string value, Func<string, T> parse)
    {
        try
        {
            return parse(value);
        }
        catch (Exception e) when (e is FormatException or OverflowException or ArgumentException)
        {
            throw new FormatException($"Configuration error: could not convert the {name} environment variable's value '{value}': {e.Message}", e);
        }
    }

    // strconv.ParseBool's spellings.
    private static bool ParseBool(string value) => value switch
    {
        "1" or "t" or "T" or "TRUE" or "true" or "True" => true,
        "0" or "f" or "F" or "FALSE" or "false" or "False" => false,
        _ => throw new FormatException("Expected a boolean: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false or False."),
    };

    // "rate:burst", or "rate" with a burst of the rate rounded down (at least 1).
    private static VaultRateLimiter ParseRateLimit(string value)
    {
        var colon = value.IndexOf(':');
        if (colon >= 0)
            return new VaultRateLimiter(
                double.Parse(value.AsSpan(0, colon), NumberStyles.Float, CultureInfo.InvariantCulture),
                int.Parse(value.AsSpan(colon + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture));

        var rate = double.Parse(value, NumberStyles.Float, CultureInfo.InvariantCulture);
        return new VaultRateLimiter(rate, Math.Max(1, (int)Math.Min(rate, int.MaxValue)));
    }
}
