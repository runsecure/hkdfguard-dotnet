namespace HkdfGuard.Cache.HashiCorpVault;

/// <summary>
/// Supplies the Vault token every read is made with. Getting that token - logging in with AppRole,
/// Kubernetes or a certificate, renewing it, replacing it before it expires - is the provider's job,
/// not the cache's, so any auth method can sit behind the cache. <see cref="StaticVaultToken"/> is
/// a token you already hold.
/// </summary>
public interface IVaultTokenProvider
{
    /// <summary>The token to make the next read with. Asked for on every fetch; the cache never keeps it.</summary>
    /// <param name="cancellationToken">Cancelled once the cache's timeout has passed.</param>
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// A token issued elsewhere - VAULT_TOKEN, say - used as it is. Nothing renews or replaces it, so
/// once it expires or is revoked every fetch fails with 403.
/// </summary>
public sealed class StaticVaultToken : IVaultTokenProvider
{
    private readonly string _token;

    /// <param name="token">The token. Held in memory as a string, which can't be zeroed.</param>
    /// <exception cref="ArgumentException">token is empty, or isn't printable ASCII without spaces</exception>
    public StaticVaultToken(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        if (!HashiCorpVaultSecretCache.IsValidToken(token))
            throw new ArgumentException("A Vault token is printable ASCII, with no spaces.", nameof(token));
        _token = token;
    }

    /// <inheritdoc/>
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => ValueTask.FromResult(_token);
}
