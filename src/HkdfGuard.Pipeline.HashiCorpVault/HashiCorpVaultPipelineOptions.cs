using HkdfGuard.Integration.HashiCorpVault;

namespace HkdfGuard.Pipeline.HashiCorpVault;

/// <summary>The version of a KV secrets engine, which decides its read path and response shape.</summary>
public enum VaultKvVersion
{
    /// <summary>KV version 1: one unversioned value per path, read at {mount}/{path}.</summary>
    V1 = 1,

    /// <summary>KV version 2: versioned secrets, read at {mount}/data/{path}; the latest version is read.</summary>
    V2 = 2,
}

/// <summary>Which KV secrets engine a <see cref="HashiCorpVaultSecretPipelineWriter"/> reads, and how it connects.</summary>
public sealed class HashiCorpVaultPipelineOptions
{
    /// <summary>Where the KV secrets engine is mounted, e.g. "secret" (the default) or "kv/team-a".</summary>
    public string MountPath { get; init; } = "secret";

    /// <summary>The engine's version. Default <see cref="VaultKvVersion.V2"/>.</summary>
    public VaultKvVersion KvVersion { get; init; } = VaultKvVersion.V2;

    /// <summary>
    /// The key read from a secret named without one: "myapp/db" reads this key of the secret at
    /// myapp/db, while "myapp/db#password" reads its password key. Default "value".
    /// </summary>
    public string DefaultKey { get; init; } = "value";

    /// <summary>The Vault Enterprise namespace every read is made in, e.g. "team-a/prod"; null for
    /// the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.</summary>
    public string? Namespace { get; init; }

    /// <summary>The fewest retries <see cref="RetryCount"/> allows.</summary>
    public const int MinRetryCount = VaultHttp.MinRetryCount;

    /// <summary>The most retries <see cref="RetryCount"/> allows.</summary>
    public const int MaxRetryCount = VaultHttp.MaxRetryCount;

    /// <summary>The longest wait between retries, before the random 0-100 ms each adds.</summary>
    public static TimeSpan MaxRetryDelay => VaultHttp.MaxRetryDelay;

    /// <summary>
    /// How long one attempt may take: getting the token, or one request and Vault's whole response.
    /// Default 30 seconds. A read that keeps failing transiently makes up to
    /// <see cref="RetryCount"/> + 1 attempts, with the waits between them.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How many times a request that failed transiently is retried: one that got no answer, lost its
    /// connection mid-response, timed out, or was answered 429 or a 5xx other than 501 (Vault answers
    /// 503 while sealed or electing a leader). <see cref="MinRetryCount"/>-<see cref="MaxRetryCount"/>; default 3.
    /// </summary>
    public int RetryCount { get; init; } = MinRetryCount;

    /// <summary>
    /// The wait before the first retry, doubling before each retry after it, up to
    /// <see cref="MaxRetryDelay"/>, plus a random 0-100 ms. Zero to <see cref="MaxRetryDelay"/>;
    /// default 200 ms.
    /// </summary>
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Sends every request, e.g. a SocketsHttpHandler trusting a private CA, or a proxy. It must not
    /// log response content. Not disposed by the writer. Null for the writer's own handler, which
    /// follows no redirects and trusts the operating system's certificate store. A handler that
    /// follows redirects is refused unless <see cref="AllowRedirects"/> is set: X-Vault-Token would
    /// go wherever the redirect points.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }

    /// <summary>
    /// Accepts an <see cref="HttpMessageHandler"/> that follows redirects, sending the Vault token
    /// along to every redirect target. Default false.
    /// </summary>
    public bool AllowRedirects { get; init; }

    /// <summary>
    /// Which CA certificates Vault's certificate must chain to, and which client certificate is
    /// presented to a Vault requiring mutual TLS (see <see cref="VaultTlsOptions"/>). Null (the
    /// default) for the operating system's trust store and no client certificate.
    /// </summary>
    public VaultTlsOptions? Tls { get; init; }
}
