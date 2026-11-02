using ConfigurationResolver.Interfaces;
using ConfigurationResolver.Providers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.ConfigurationResolver;

/// <summary>
/// A ConfigurationResolver value provider over an IProtectedReadOnlyCache, so the items in a
/// template - "Password=${db-password}" - resolve from HkdfGuard's protected caches: ProtectedCache,
/// FilePerSecretCache, a ProtectedConfigurationRoot, or a remote secret store's cache (HashiCorp
/// Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager). A template's key is the
/// cache's name as it is, so a remote cache's "app-config#api-key" form works unchanged.
/// <para>
/// Each value is decrypted straight into the resolver's destination when the cache's upper bound on
/// its length fits there, and otherwise into a stack or pinned buffer that is zeroed once the value
/// has been copied out. It is never a string: <see cref="TryGetValue"/>, the one IValueProvider
/// member that returns one, throws unless <see cref="AllowStringValues"/> is set. The resolver itself
/// never calls it.
/// </para>
/// <para>
/// IValueProvider is synchronous, so a remote cache fetches a value it hasn't cached yet by blocking
/// the resolving thread. Call <see cref="PrefetchAsync(IConfigurationItemReader, CancellationToken)"/>
/// with the template's reader first: the cache keeps what it fetches, so Resolve then reads only
/// from memory.
/// </para>
/// </summary>
public sealed class ProtectedCacheValueProvider(IProtectedReadOnlyCache cache) : ValueProviderBase
{
    private readonly IProtectedReadOnlyCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));

    /// <summary>The cache values are read from.</summary>
    public IProtectedReadOnlyCache Cache => _cache;

    /// <summary>
    /// Whether <see cref="TryGetValue"/> may return a value as a string, which can't be zeroed. False
    /// by default, when it throws InvalidOperationException instead.
    /// </summary>
    public bool AllowStringValues { get; init; }

    /// <summary>
    /// Fetches every key the reader has read, without blocking, so a later Resolve doesn't fetch. A key
    /// the cache doesn't have is skipped; Resolve reports it.
    /// </summary>
    /// <param name="reader">The reader the resolver was given, after it has read the template</param>
    /// <param name="cancellationToken">Cancels waiting for a fetch</param>
    public Task PrefetchAsync(IConfigurationItemReader reader, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return PrefetchAsync(reader.Keys(), cancellationToken);
    }

    /// <summary>
    /// Fetches each of <paramref name="keys"/>, one at a time and without blocking, so a later Resolve
    /// doesn't fetch. A key the cache doesn't have is skipped; Resolve reports it.
    /// </summary>
    /// <param name="keys">The keys to fetch; a key listed twice is fetched once</param>
    /// <param name="cancellationToken">Cancels waiting for a fetch</param>
    public async Task PrefetchAsync(IEnumerable<string> keys, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keys);

        foreach (var key in keys.Distinct(StringComparer.Ordinal))
            await _cache.GetMaxDecryptedLengthAsync(key, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override ValueStatus TryGetBytes(string key, Span<byte> destination, out int bytesWritten)
    {
        ArgumentNullException.ThrowIfNull(key);
        bytesWritten = 0;

        if (!_cache.TryGetMaxDecryptedLength(key, out var maxLength))
            return ValueStatus.NotFound;

        if (maxLength <= destination.Length)
        {
            bytesWritten = _cache.Decrypt(key, destination);
            return ValueStatus.Found;
        }

        // The bound is above the room left, but the value itself may still fit.
        Span<byte> plaintext = maxLength <= ArrayUtility.MaxStackBytes
            ? stackalloc byte[maxLength]
            : ArrayUtility.AllocatePinned<byte>(maxLength);
        try
        {
            var length = _cache.Decrypt(key, plaintext);
            if (length > destination.Length)
                return ValueStatus.DestinationTooSmall;

            plaintext[..length].CopyTo(destination);
            bytesWritten = length;
            return ValueStatus.Found;
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    /// <inheritdoc/>
    public override ValueStatus TryGetChar(string key, Span<char> destination, out int charsWritten)
    {
        ArgumentNullException.ThrowIfNull(key);
        charsWritten = 0;

        // The bound counts UTF-8 bytes, and a value never has more chars than that.
        if (!_cache.TryGetMaxDecryptedLength(key, out var maxLength))
            return ValueStatus.NotFound;

        if (maxLength <= destination.Length)
        {
            charsWritten = _cache.Decrypt(key, destination);
            return ValueStatus.Found;
        }

        Span<char> plaintext = maxLength <= ArrayUtility.MaxStackChars
            ? stackalloc char[maxLength]
            : ArrayUtility.AllocatePinned<char>(maxLength);
        try
        {
            var length = _cache.Decrypt(key, plaintext);
            if (length > destination.Length)
                return ValueStatus.DestinationTooSmall;

            plaintext[..length].CopyTo(destination);
            charsWritten = length;
            return ValueStatus.Found;
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException"><see cref="AllowStringValues"/> isn't set</exception>
    public override ValueStatus TryGetValue(string key, out string? value)
    {
        if (!AllowStringValues)
            throw new InvalidOperationException(
                $"{nameof(ProtectedCacheValueProvider)} doesn't return values as strings unless {nameof(AllowStringValues)} is set.");

        return base.TryGetValue(key, out value);
    }

    /// <inheritdoc/>
    protected override bool TryGetByteCount(string key, out int byteCount)
        => _cache.TryGetMaxDecryptedLength(key, out byteCount);
}
