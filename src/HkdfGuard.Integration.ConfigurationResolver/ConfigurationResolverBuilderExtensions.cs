using ConfigurationResolver.Interfaces;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.ConfigurationResolver;

/// <summary>Adds HkdfGuard's protected caches to a ConfigurationResolver builder.</summary>
public static class ConfigurationResolverBuilderExtensions
{
    /// <summary>
    /// Adds a <see cref="ProtectedCacheValueProvider"/> over <paramref name="cache"/>, after any value
    /// provider added already.
    /// </summary>
    /// <param name="builder">The builder</param>
    /// <param name="cache">The cache to read values from</param>
    /// <returns>The builder</returns>
    public static IConfigurationResolverBuilder AddProtectedCache(this IConfigurationResolverBuilder builder, IProtectedReadOnlyCache cache)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddValueProvider(new ProtectedCacheValueProvider(cache));
    }
}
