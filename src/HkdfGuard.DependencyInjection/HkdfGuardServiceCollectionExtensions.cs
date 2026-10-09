using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Registers a KeyRing into an IServiceCollection.
/// </summary>
public static class HkdfGuardServiceCollectionExtensions
{
    /// <summary>
    /// Builds a KeyRing asynchronously - reading its key files and revealing every key through the
    /// key wrapper without blocking a thread - and registers it as a singleton. The DI container
    /// can't construct services asynchronously, so the ring is built here, at registration, before
    /// the container exists:
    /// <code>
    /// await builder.Services.AddKeyRingAsync(ring => ring
    ///     .WithKeyWrapper(new NativeHkdfKeyWrapperV1("myservice"))
    ///     .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    ///     .WithCachedKeyExpiry(60)
    ///     .WithKeyFile(1, "/path/to/wrapped-dek-v1.bin"));
    /// </code>
    /// The container owns the ring and disposes it - asynchronously, with DisposeAsync - at
    /// shutdown. If a KeyRing is already registered this does nothing, and the configuration is
    /// never built, so no keys are revealed for a ring that would be discarded.
    /// </summary>
    /// <param name="services">The service collection to register the ring in.</param>
    /// <param name="configure">Configures a fresh KeyRingBuilder; BuildAsync is called on the result.</param>
    /// <param name="cancellationToken">Cancels building the ring.</param>
    /// <returns>The same service collection, for chaining.</returns>
    public static async Task<IServiceCollection> AddKeyRingAsync(this IServiceCollection services,
        Func<KeyRingBuilder, KeyRingBuilder> configure, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(KeyRing)))
            return services;

        var ring = await configure(new KeyRingBuilder()).BuildAsync(cancellationToken).ConfigureAwait(false);

        // Registered through a factory (not as an instance) so the container takes ownership and
        // disposes the ring at shutdown.
        services.AddSingleton(_ => ring);

        // The same instance as IKeyRing, which the protected caches take - so a ProtectedCache
        // registered in the container encrypts through, and rotates with, this ring.
        services.AddSingleton<IKeyRing>(provider => provider.GetRequiredService<KeyRing>());
        return services;
    }
}
