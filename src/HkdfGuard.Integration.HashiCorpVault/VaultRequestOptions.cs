namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// Settings for one request: vault-client-go's RequestOption. They combine with the client's own
/// (<see cref="VaultClient.SetToken(IVaultTokenProvider)"/> and the rest) this way: a single value set
/// here wins over the client's; a list here is added to the client's; a header here replaces the
/// client's header of the same name and keeps the rest.
/// </summary>
public sealed record VaultRequestOptions
{
    /// <summary>The token to make this request with, instead of the client's.</summary>
    public IVaultTokenProvider? Token { get; init; }

    /// <summary>The namespace to make this request in, instead of the client's; null or empty keeps the client's.</summary>
    public string? Namespace { get; init; }

    /// <summary>
    /// Multi-factor credentials (X-Vault-MFA), added to the client's; see
    /// https://developer.hashicorp.com/vault/docs/auth/login-mfa.
    /// </summary>
    public IReadOnlyList<string>? MfaCredentials { get; init; }

    /// <summary>
    /// Asks Vault to wrap the response for this long (X-Vault-Wrap-TTL) instead of returning it: the
    /// response holds only <see cref="VaultResponse{T}.WrapInfo"/>, for
    /// <see cref="VaultClient.UnwrapAsync{T}"/>. Null or zero keeps the client's setting; see
    /// https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
    /// </summary>
    public TimeSpan? ResponseWrappingTtl { get; init; }

    /// <summary>Headers to add, over the client's; names starting X-Vault- are the client's own and refused.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? CustomHeaders { get; init; }

    /// <summary>Called with each attempt's request before it's sent, after the client's own callbacks. The token isn't on it yet.</summary>
    public IReadOnlyList<Action<HttpRequestMessage>>? RequestCallbacks { get; init; }

    /// <summary>Called with the request and its response once Vault has answered, after the client's own callbacks.</summary>
    public IReadOnlyList<Action<HttpRequestMessage, HttpResponseMessage>>? ResponseCallbacks { get; init; }

    /// <summary>
    /// Where the auth method or secrets engine is mounted, instead of its default - for the generated
    /// <see cref="VaultClient.Auth"/> and <see cref="VaultClient.Secrets"/> methods; leading and trailing
    /// '/' are ignored.
    /// </summary>
    public string? MountPath { get; init; }

    /// <summary>Query parameters to add to the request; meant for the generic Read, ReadRaw, List and Delete.</summary>
    public IReadOnlyList<KeyValuePair<string, string>>? QueryParameters { get; init; }

    /// <summary>Whether a performance standby forwards this request to the active node; None keeps the client's.</summary>
    public ReplicationForwardingMode ReplicationForwardingMode { get; init; }
}

/// <summary>
/// The headers and callbacks a client adds to every request. Immutable: the client swaps in a new one
/// when a setting changes, so a request in flight keeps the settings it started with.
/// </summary>
internal sealed record RequestModifiers
{
    public string? UserAgent { get; init; }
    public IVaultTokenProvider? Token { get; init; }
    public string? Namespace { get; init; }
    public IReadOnlyList<string> MfaCredentials { get; init; } = [];
    public TimeSpan ResponseWrappingTtl { get; init; }
    public ReplicationForwardingMode ReplicationForwardingMode { get; init; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>> CustomHeaders { get; init; } = new Dictionary<string, IReadOnlyList<string>>();
    public IReadOnlyList<Action<HttpRequestMessage>> RequestCallbacks { get; init; } = [];
    public IReadOnlyList<Action<HttpRequestMessage, HttpResponseMessage>> ResponseCallbacks { get; init; } = [];

    /// <summary>
    /// These with options' over them: options' single values win, its lists are appended, and its
    /// headers replace these headers of the same name.
    /// </summary>
    /// <exception cref="ArgumentException">options holds a namespace, MFA credential or header that can't be sent</exception>
    public RequestModifiers Merge(VaultRequestOptions? options)
    {
        if (options is null)
            return this;

        if (!string.IsNullOrEmpty(options.Namespace) && !VaultClient.IsValidNamespace(options.Namespace))
            throw new ArgumentException($"The namespace '{options.Namespace}' contains non-printable characters.", nameof(options));
        ValidateMfaCredentials(options.MfaCredentials ?? []);
        ValidateCustomHeaders(options.CustomHeaders);

        var headers = CustomHeaders;
        if (options.CustomHeaders is { Count: > 0 })
        {
            var merged = new Dictionary<string, IReadOnlyList<string>>(CustomHeaders, StringComparer.OrdinalIgnoreCase);
            foreach (var (name, values) in options.CustomHeaders)
                merged[name] = [.. values];
            headers = merged;
        }

        return this with
        {
            Token = options.Token ?? Token,
            Namespace = string.IsNullOrEmpty(options.Namespace) ? Namespace : options.Namespace,
            MfaCredentials = [.. MfaCredentials, .. options.MfaCredentials ?? []],
            ResponseWrappingTtl = options.ResponseWrappingTtl is { } ttl && ttl != TimeSpan.Zero ? ttl : ResponseWrappingTtl,
            ReplicationForwardingMode = options.ReplicationForwardingMode != ReplicationForwardingMode.None
                ? options.ReplicationForwardingMode
                : ReplicationForwardingMode,
            CustomHeaders = headers,
            RequestCallbacks = [.. RequestCallbacks, .. options.RequestCallbacks ?? []],
            ResponseCallbacks = [.. ResponseCallbacks, .. options.ResponseCallbacks ?? []],
        };
    }

    /// <exception cref="ArgumentException">A credential can't go in a header</exception>
    public static void ValidateMfaCredentials(IReadOnlyList<string> credentials)
    {
        foreach (var credential in credentials)
        {
            if (string.IsNullOrEmpty(credential) || !VaultClient.IsValidNamespace(credential))
                throw new ArgumentException("An MFA credential must be non-empty printable ASCII.", nameof(credentials));
        }
    }

    /// <exception cref="ArgumentException">A header is named X-Vault-*, or has no name</exception>
    public static void ValidateCustomHeaders(IReadOnlyDictionary<string, IReadOnlyList<string>>? headers)
    {
        if (headers is null)
            return;

        foreach (var name in headers.Keys)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("A custom header must have a name.", nameof(headers));
            if (name.StartsWith("X-Vault-", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"The custom header '{name}' isn't allowed: the 'X-Vault-' prefix is for the client's own use.", nameof(headers));
        }
    }
}
