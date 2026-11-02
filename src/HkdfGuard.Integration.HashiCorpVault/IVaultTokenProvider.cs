using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// Supplies a Vault token, protected: as the token protector of whatever uses it encrypted it
/// (tokenProtector.Encrypt(token)), never the token itself - <see cref="VaultClient"/>'s, or
/// HashiCorpVaultSecretCache's. Asked for once per request or fetch; the token is decrypted only to
/// put it in that request's X-Vault-Token header, and that copy is zeroed as soon as the request has
/// been sent. Logging in, renewing and replacing tokens are the provider's business, so any auth
/// method can sit behind it; <see cref="StaticVaultToken"/> is a token you already hold. Code that
/// runs before there is a key ring uses <see cref="IVaultTokenSource"/> instead.
/// </summary>
public interface IVaultTokenProvider
{
    /// <summary>
    /// The token to make the next request with, protected by the user's token protector. A token
    /// that isn't protected so fails the request with InvalidOperationException.
    /// </summary>
    /// <param name="cancellationToken">The request's cancellation, including its timeout.</param>
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);
}

/// <summary>
/// A token held only in protected form: one issued elsewhere (VAULT_TOKEN, say), or one Vault
/// returned to a <see cref="VaultClient"/> - <see cref="VaultResponseAuth.ClientToken"/> after a
/// login, or <see cref="VaultResponseWrapInfo.Token"/> for a wrapped response - which the client
/// protects as it reads the response, so it never becomes a string. Nothing renews or replaces it,
/// so once it expires or is revoked every request fails with 403.
/// </summary>
public sealed class StaticVaultToken : IVaultTokenProvider
{
    private readonly string _protectedToken;

    /// <param name="protectedToken">The token as its user's token protector protected it
    /// (tokenProtector.Encrypt(token)), never the token itself; see <see cref="Protect"/>.</param>
    /// <exception cref="ArgumentException">protectedToken is empty</exception>
    public StaticVaultToken(string protectedToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedToken);
        _protectedToken = protectedToken;
    }

    /// <summary>
    /// Protects token with tokenProtector - the protector the client or cache is given - and holds
    /// only the result. token is read-only, so it isn't zeroed: clear it once this returns.
    /// </summary>
    /// <exception cref="ArgumentNullException">tokenProtector is null</exception>
    /// <exception cref="ArgumentException">token is empty, or isn't printable ASCII without spaces</exception>
    public static StaticVaultToken Protect(IDataProtector tokenProtector, ReadOnlySpan<char> token)
    {
        ArgumentNullException.ThrowIfNull(tokenProtector);
        if (!VaultHttp.IsValidToken(token))
            throw new ArgumentException("A Vault token is printable ASCII, with no spaces.", nameof(token));

        return new StaticVaultToken(tokenProtector.Encrypt(token));
    }

    /// <inheritdoc/>
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => ValueTask.FromResult(_protectedToken);

    /// <summary>The protected token: what <see cref="GetTokenAsync"/> returns, never the token itself.</summary>
    public override string ToString() => _protectedToken;
}
