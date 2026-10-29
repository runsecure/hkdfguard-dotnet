using HkdfGuard.Abstractions;

namespace HkdfGuard.KeyWrapping.HashiCorpVault;

/// <summary>
/// Supplies the Vault token every transit request is made with. Getting that token - logging in
/// with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires - is the
/// source's job, not the wrapper's, so any auth method can sit behind it.
/// <see cref="StaticVaultTokenSource"/> is a token you already hold.
/// <para>
/// The token is copied into a buffer the wrapper owns, pinned and zeroed once the request has been
/// sent, rather than returned as a string that would live until collected. (The cache's
/// IVaultTokenProvider hands its token over protected by the key ring instead; a key wrapper can't,
/// since it runs before there is a key ring.)
/// </para>
/// </summary>
public interface IVaultTokenSource
{
    /// <summary>
    /// Copies the token to make the next request with into destination. Asked for once per wrap,
    /// unwrap or generate - not per retry. A token that is empty or isn't printable ASCII without
    /// spaces fails the call.
    /// </summary>
    /// <param name="destination">Where to write the token:
    /// <see cref="HashiCorpVaultTransitKeyWrapper.MaxTokenLength"/> characters.</param>
    /// <param name="cancellationToken">Cancelled once the wrapper's timeout has passed.</param>
    /// <returns>The number of characters written.</returns>
    ValueTask<int> CopyTokenAsync(Memory<char> destination, CancellationToken cancellationToken);
}

/// <summary>
/// A token issued elsewhere - VAULT_TOKEN, say - held in pinned memory and zeroed on Dispose.
/// Nothing renews or replaces it, so once it expires or is revoked every request fails with 403.
/// </summary>
public sealed class StaticVaultTokenSource : IVaultTokenSource, IDisposable
{
    private readonly char[] _token;

    /// <param name="token">The token, copied. It is read-only, so it isn't zeroed: clear it once
    /// this returns.</param>
    /// <exception cref="ArgumentException">token is empty, longer than
    /// <see cref="HashiCorpVaultTransitKeyWrapper.MaxTokenLength"/>, or isn't printable ASCII
    /// without spaces</exception>
    public StaticVaultTokenSource(ReadOnlySpan<char> token)
    {
        if (!HashiCorpVaultTransitKeyWrapper.IsValidToken(token) || token.Length > HashiCorpVaultTransitKeyWrapper.MaxTokenLength)
            throw new ArgumentException(
                $"A Vault token is 1-{HashiCorpVaultTransitKeyWrapper.MaxTokenLength} printable ASCII characters, with no spaces.", nameof(token));

        _token = ArrayUtility.AllocatePinned<char>(token.Length);
        token.CopyTo(_token);
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentException">destination is too small for the token</exception>
    public ValueTask<int> CopyTokenAsync(Memory<char> destination, CancellationToken cancellationToken)
    {
        if (destination.Length < _token.Length)
            throw new ArgumentException($"The token is {_token.Length} characters; destination holds {destination.Length}.", nameof(destination));

        _token.CopyTo(destination.Span);
        return ValueTask.FromResult(_token.Length);
    }

    /// <summary>Zeroes the token. A request made afterwards fails, its token no longer one.</summary>
    public void Dispose() => ArrayUtility.ZeroMemory(_token.AsSpan());
}
