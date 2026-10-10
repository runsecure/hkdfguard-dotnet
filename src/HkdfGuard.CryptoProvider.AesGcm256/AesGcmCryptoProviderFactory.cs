using HkdfGuard.Abstractions;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <param name="logger">Handed to every provider this factory creates, which logs each failed
/// background refresh, key-access suspension and resumption, and an approaching encryption limit
/// to it. Optional, but strongly recommended: it is how an operator learns that a KEK has been
/// revoked or become unreachable, or that a key needs rotating.</param>
public class AesGcmCryptoProviderFactory(ILogger<AesGcmCryptoProvider>? logger = null) : ICryptoProviderFactory
{
    /// <inheritdoc/>
    public async ValueTask<ICryptoProvider> CreateAsync(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds,
        int? maxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures, CancellationToken cancellationToken = default)
        => await AesGcmCryptoProvider.CreateAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures, cancellationToken, logger)
            .ConfigureAwait(false);

    /// <inheritdoc/>
    public async ValueTask<ICryptoProvider> CreateEphemeralAsync(IKeyWrapper wrapper, int expirySeconds,
        int? maxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures, CancellationToken cancellationToken = default)
    {
        // Fail on bad arguments before asking the key wrapper to generate anything.
        AesGcmCryptoProvider.Validate(expirySeconds, maxRefreshFailures);
        cancellationToken.ThrowIfCancellationRequested();

        // Sized to the same limit a key file is held to; trimmed to what GenerateAndWrapAsync wrote.
        var buffer = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(buffer, cancellationToken).ConfigureAwait(false);
        return await AesGcmCryptoProvider.CreateAsync(wrapper, buffer[..length], expirySeconds, maxRefreshFailures, cancellationToken, logger)
            .ConfigureAwait(false);
    }
}
