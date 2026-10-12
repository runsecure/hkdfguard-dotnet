namespace HkdfGuard.Abstractions;

/// <summary>
/// Mints ICryptoProviders for a KeyRing. Creation is asynchronous because building a provider
/// reveals its first key through the IKeyWrapper, which for a network-backed key wrapper is a
/// remote call. Every provider then refreshes its revealed key every <c>expirySeconds</c>;
/// <c>maxRefreshFailures</c> is the refresh-failure policy: a value makes the provider fail closed -
/// dispose its key and refuse every operation - once that many consecutive refreshes have failed,
/// until one succeeds again, while null keeps serving on the last good key no matter how many
/// refreshes fail (fail open). It defaults to failing closed, after
/// <see cref="RefreshFailurePolicy.DefaultMaxRefreshFailures"/> failures.
/// </summary>
public interface ICryptoProviderFactory
{
    /// <param name="wrapper">Reveals the DEK.</param>
    /// <param name="wrapped">The wrapped DEK payload (e.g. a key file's bytes). Owned by the
    /// provider from here on; zeroed when it's disposed.</param>
    /// <param name="expirySeconds">Session lifetime and background refresh interval, 1-300.</param>
    /// <param name="maxRefreshFailures">Consecutive failed refreshes tolerated before failing
    /// closed, at least 1; null to fail open.</param>
    /// <param name="cancellationToken">Cancels the first key reveal.</param>
    public ValueTask<ICryptoProvider> CreateAsync(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds,
        int? maxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures, CancellationToken cancellationToken = default);

    /// <param name="wrapper">Generates and wraps a fresh DEK (IKeyWrapper.GenerateAndWrapAsync), then reveals it.</param>
    /// <param name="expirySeconds">Session lifetime and background refresh interval, 1-300.</param>
    /// <param name="maxRefreshFailures">See <see cref="CreateAsync"/>.</param>
    /// <param name="cancellationToken">Cancels generating and first revealing the key.</param>
    public ValueTask<ICryptoProvider> CreateEphemeralAsync(IKeyWrapper wrapper, int expirySeconds,
        int? maxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures, CancellationToken cancellationToken = default);
}
