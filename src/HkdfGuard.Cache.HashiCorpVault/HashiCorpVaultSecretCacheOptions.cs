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

    /// <summary>How long one fetch may take, its token and Vault's whole response included. Default 30 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Sends every request, e.g. a SocketsHttpHandler trusting a private CA, or a proxy. It must not
    /// follow redirects, which would carry the token wherever they point, nor log response content.
    /// Not disposed by the cache. Null for the cache's own handler, which follows no redirects and
    /// trusts the operating system's certificate store.
    /// </summary>
    public HttpMessageHandler? HttpMessageHandler { get; init; }
}
