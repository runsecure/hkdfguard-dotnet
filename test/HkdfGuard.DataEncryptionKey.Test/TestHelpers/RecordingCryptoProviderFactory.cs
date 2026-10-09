using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// An ICryptoProviderFactory that delegates to a real AesGcmCryptoProviderFactory (so callers get
/// a genuinely working ICryptoProvider back) while recording the arguments each method was
/// called with - lets KeyRingBuilder tests assert exactly what it passes through without
/// depending on AesGcmCryptoProvider exposing its own configuration for inspection.
/// </summary>
internal sealed class RecordingCryptoProviderFactory : ICryptoProviderFactory
{
    private readonly AesGcmCryptoProviderFactory _inner = new();

    public List<int> CreateExpirySecondsCalls { get; } = [];
    public List<int> CreateEphemeralExpirySecondsCalls { get; } = [];
    public List<ICryptoProvider> CreatedProviders { get; } = [];
    public List<int?> MaxRefreshFailuresCalls { get; } = [];

    /// <summary>A copy of each wrapped payload CreateAsync received (the provider zeroes the original on dispose).</summary>
    public List<byte[]> CreatedWrapped { get; } = [];

    /// <summary>Runs after each provider is created - e.g. to cancel a build partway through.</summary>
    public Action? AfterEachCreate { get; set; }

    public async ValueTask<ICryptoProvider> CreateAsync(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds,
        int? maxRefreshFailures = null, CancellationToken cancellationToken = default)
    {
        CreateExpirySecondsCalls.Add(expirySeconds);
        MaxRefreshFailuresCalls.Add(maxRefreshFailures);
        CreatedWrapped.Add((byte[])wrapped.Clone());
        var provider = await _inner.CreateAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures, cancellationToken);
        CreatedProviders.Add(provider);
        AfterEachCreate?.Invoke();
        return provider;
    }

    public async ValueTask<ICryptoProvider> CreateEphemeralAsync(IKeyWrapper wrapper, int expirySeconds,
        int? maxRefreshFailures = null, CancellationToken cancellationToken = default)
    {
        CreateEphemeralExpirySecondsCalls.Add(expirySeconds);
        MaxRefreshFailuresCalls.Add(maxRefreshFailures);
        var provider = await _inner.CreateEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures, cancellationToken);
        CreatedProviders.Add(provider);
        AfterEachCreate?.Invoke();
        return provider;
    }
}
