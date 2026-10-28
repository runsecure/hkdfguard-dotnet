namespace HkdfGuard.Cache.HashiCorpVault;

/// <summary>The version of a KV secrets engine, which decides its read path and response shape.</summary>
public enum VaultKvVersion
{
    /// <summary>KV version 1: one unversioned value per path, read at {mount}/{path}.</summary>
    V1 = 1,

    /// <summary>KV version 2: versioned secrets, read at {mount}/data/{path}; the latest version is read.</summary>
    V2 = 2,
}

/// <summary>Which KV secrets engine a <see cref="HashiCorpVaultSecretCache"/> reads, and how it connects.</summary>
public sealed class HashiCorpVaultSecretCacheOptions
{
    /// <summary>Where the KV secrets engine is mounted, e.g. "secret" (the default) or "kv/team-a".</summary>
    public string MountPath { get; init; } = "secret";

    /// <summary>The engine's version. Default <see cref="VaultKvVersion.V2"/>.</summary>
    public VaultKvVersion KvVersion { get; init; } = VaultKvVersion.V2;

    /// <summary>
    /// The key read from a secret looked up without one: "myapp/db" reads this key of the secret at
    /// myapp/db, while "myapp/db#password" reads its password key. Default "value".
    /// </summary>
    public string DefaultKey { get; init; } = "value";

    /// <summary>The Vault Enterprise namespace every read is made in, e.g. "team-a/prod"; null for
    /// the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.</summary>
    public string? Namespace { get; init; }

    /// <summary>The fewest retries <see cref="RetryCount"/> allows.</summary>
    public const int MinRetryCount = 3;

    /// <summary>The most retries <see cref="RetryCount"/> allows.</summary>
    public const int MaxRetryCount = 10;

    /// <summary>The longest wait between retries, before the random 0-100 ms each adds.</summary>
    public static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How long one attempt may take: getting the token, or one request and Vault's whole response.
    /// Default 30 seconds. A fetch that keeps failing transiently makes up to
    /// <see cref="RetryCount"/> + 1 attempts, with the waits between them.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How many times a request that failed transiently is retried: one that got no answer
    /// (connection refused or reset, DNS), lost its connection mid-response, timed out, or was
    /// answered 429 or a 5xx other than 501 (Vault answers 503 while sealed or electing a leader).
    /// Anything else - 403, a 404 naming an error, a token provider's failure, the caller's
    /// cancellation - isn't retried. <see cref="MinRetryCount"/>-<see cref="MaxRetryCount"/>; default 3.
    /// </summary>
    public int RetryCount { get; init; } = MinRetryCount;

    /// <summary>
    /// The wait before the first retry, doubling before each retry after it, up to
    /// <see cref="MaxRetryDelay"/>. Every wait also adds a random 0-100 ms, so many clients
    /// reconnecting at once - after a network outage, say - don't all retry together. Zero to
    /// <see cref="MaxRetryDelay"/>; default 200 ms.
    /// </summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Sends every request, e.g. a SocketsHttpHandler trusting a private CA, or a proxy. It must not
    /// log response content. Not disposed by the cache. Null for the cache's own handler, which
    /// follows no redirects and trusts the operating system's certificate store.
    /// <para>
    /// A handler that follows redirects is refused unless <see cref="AllowRedirects"/> is set: when
    /// .NET follows a redirect it drops only the Authorization header, so X-Vault-Token would go
    /// wherever the redirect points. Set AllowAutoRedirect to false on a SocketsHttpHandler or
    /// HttpClientHandler - both default to true. The handler at the bottom of a chain of
    /// DelegatingHandlers is the one checked; one of another type can't be, and is accepted.
    /// </para>
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }

    /// <summary>
    /// Accepts an <see cref="HttpMessageHandler"/> that follows redirects, sending the Vault token
    /// along to every redirect target. Set it only when every address a redirect could lead to may
    /// see the token. Default false.
    /// </summary>
    public bool AllowRedirects { get; init; }
}
