using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Cache;

/// <summary>
/// Aggregates multiple IProtectedReadOnlyCache sources into a single read-only surface. Add
/// registers a source and returns this same instance for fluent chaining (e.g.
/// new ProtectedCacheCollection().Add(a).Add(b)). Decrypt/TryGetMaxDecryptedLength check each
/// registered source in the order it was added, returning the first match. This never owns or
/// writes any encrypted values of its own - Add here only registers a source, it never protects
/// or stores a value - so mutation of actual cached values stays entirely a concern of whichever
/// underlying source(s) actually support it (e.g. a writable ProtectedCache mixed in as one of
/// the sources).
/// </summary>
public sealed class ProtectedCacheCollection : IProtectedReadOnlyCache
{
    private readonly List<IProtectedReadOnlyCache> _sources = [];

    /// <summary>
    /// Registers source as an additional lookup source, checked after every source already
    /// added.
    /// </summary>
    /// <returns>This same ProtectedCacheCollection, for fluent chaining</returns>
    public ProtectedCacheCollection Add(IProtectedReadOnlyCache source)
    {
        _sources.Add(source);
        return this;
    }

    /// <inheritdoc/>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));

        try
        {
            foreach (var source in _sources)
            {
                var written = source.Decrypt(name, result);
                if (written > 0)
                    return written;
            }

            return 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));

        try
        {
            foreach (var source in _sources)
            {
                var written = source.Decrypt(name, result);
                if (written > 0)
                    return written;
            }

            return 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        foreach (var source in _sources)
        {
            if (source.TryGetMaxDecryptedLength(name, out maxLength))
                return true;
        }

        maxLength = 0;
        return false;
    }

    /// <inheritdoc/>
    /// <remarks>Each source is asked with its own DecryptAsync, so one that fetches over the network
    /// doesn't block.</remarks>
    public async ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            foreach (var source in _sources)
            {
                var written = await source.DecryptAsync(name, result, cancellationToken).ConfigureAwait(false);
                if (written > 0)
                    return written;
            }

            return 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <remarks>Each source is asked with its own DecryptAsync, so one that fetches over the network
    /// doesn't block.</remarks>
    public async ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            foreach (var source in _sources)
            {
                var written = await source.DecryptAsync(name, result, cancellationToken).ConfigureAwait(false);
                if (written > 0)
                    return written;
            }

            return 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public async ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
    {
        foreach (var source in _sources)
        {
            var maxLength = await source.GetMaxDecryptedLengthAsync(name, cancellationToken).ConfigureAwait(false);
            if (maxLength > 0)
                return maxLength;
        }

        return 0;
    }

    private static System.Diagnostics.Activity? StartDecryptActivity(string name)
    {
        var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));
        return activity;
    }
}
