using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.HashiCorpVault;

/// <summary>
/// Supplies the Vault token every read is made with, protected: as the cache's token protector
/// encrypted it (tokenProtector.Encrypt(token)), never the token itself. Getting that token -
/// logging in with AppRole, Kubernetes or a certificate, renewing it, replacing it before it
/// expires - is the provider's job, not the cache's, so any auth method can sit behind the cache.
/// <see cref="StaticVaultToken"/> is a token you already hold.
/// </summary>
public interface IVaultTokenProvider
{
    /// <summary>
    /// The token to make the next read with, protected by the cache's token protector. Asked for
    /// on every fetch; the cache never keeps it, and decrypts it only to put it in that fetch's
    /// request. A token that isn't protected so fails the fetch.
    /// </summary>
    /// <param name="cancellationToken">Cancelled once the cache's timeout has passed.</param>
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// A token issued elsewhere - VAULT_TOKEN, say - held only in protected form. Nothing renews or
/// replaces it, so once it expires or is revoked every fetch fails with 403.
/// </summary>
public sealed class StaticVaultToken : IVaultTokenProvider
{
    private readonly string _protectedToken;

    /// <param name="protectedToken">The token as the cache's token protector protected it
    /// (tokenProtector.Encrypt(token)), never the token itself; see <see cref="Protect"/>.</param>
    /// <exception cref="ArgumentException">protectedToken is empty</exception>
    public StaticVaultToken(string protectedToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedToken);
        _protectedToken = protectedToken;
    }

    /// <summary>
    /// Protects token with tokenProtector - the protector the cache is given - and holds only the
    /// result. token is read-only, so it isn't zeroed: clear it once this returns.
    /// </summary>
    /// <exception cref="ArgumentNullException">tokenProtector is null</exception>
    /// <exception cref="ArgumentException">token is empty, or isn't printable ASCII without spaces</exception>
    public static StaticVaultToken Protect(IDataProtector tokenProtector, ReadOnlySpan<char> token)
    {
        ArgumentNullException.ThrowIfNull(tokenProtector);
        if (!HashiCorpVaultSecretCache.IsValidToken(token))
            throw new ArgumentException("A Vault token is printable ASCII, with no spaces.", nameof(token));

        return new StaticVaultToken(tokenProtector.Encrypt(token));
    }

    /// <inheritdoc/>
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => ValueTask.FromResult(_protectedToken);
}
