using System.Collections.Concurrent;
using System.Text;
using ConfigurationResolver.Interfaces;
using ConfigurationResolver.Readers;
using ConfigurationResolver.Resolvers;
using ConfigurationResolver.Tokens;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Integration.ConfigurationResolver;

/// <summary>
/// ProtectedCacheCollection with templates: aggregates IProtectedReadOnlyCache sources, checked in
/// the order they were added, and resolves a value holding ConfigurationResolver items -
/// "Host=db;Password=${db-password}" - on its first lookup, from those same sources (then any value
/// providers added with <see cref="AddValueProvider"/>). The resolved value is encrypted under the
/// ring's current key, bound to its name as every ProtectedCacheBase entry is, and cached, so later
/// lookups only decrypt it. A value without items is answered by its source, unchanged.
/// <para>
/// <b>Only a template source's values are templates.</b> A template's items may name any value in
/// any source, so whoever can write a template can read, through this application, every secret the
/// application can. Sources are therefore added in one of two ways. <see cref="AddTemplateSource"/>
/// registers a source whose values are resolved when they hold items: the application's own
/// configuration, written only by its deployment pipeline. <see cref="Add"/> registers a source whose
/// values are answered exactly as stored, items or not, and are never resolved: a shared secret store
/// whose paths other parties can write. Both kinds answer names and supply a template's items. A
/// template that names a value in a plain source reads it as intended; a value in a plain source that
/// happens to hold <c>${...}</c> is returned verbatim, and nothing it names is looked up.
/// </para>
/// <para>
/// Items are resolved one level deep: an item whose value is itself a template inserts that
/// template's text unresolved. A value that is a template but names a value no source or provider
/// has throws ConfigurationKeyException on lookup, rather than reporting the name missing. One that
/// resolves to nothing is reported missing, as an empty value can't be cached.
/// </para>
/// <para>
/// <b>Resolved values are kept until invalidated.</b> When a value a template uses changes - a
/// ProtectedCache.AddOrUpdate, a configuration reload, a rotated remote secret - call
/// <see cref="Invalidate"/> for the template's name, or <see cref="Clear"/>; the next lookup resolves
/// it again. A resolution already under way when either is called doesn't cache its result. Which
/// source holds a value without items is remembered too, and forgotten the same way. Add every
/// source and provider before the first lookup.
/// </para>
/// <para>
/// A source that throws fails the lookup, as in ProtectedCacheCollection, and the same advice holds:
/// add local sources before remote ones. DecryptAsync and GetMaxDecryptedLengthAsync find the value
/// and every value its template names with each source's async members, so a remote source doesn't
/// block; the synchronous members block on a remote fetch.
/// </para>
/// </summary>
public sealed class ResolvingProtectedCacheCollection : IProtectedReadOnlyCache
{
    /// <summary>The default <see cref="MaxResolvedLength"/>: 1 MiB.</summary>
    public const int DefaultMaxResolvedLength = 1 << 20;

    private readonly List<IProtectedReadOnlyCache> _sources = [];
    // The sources whose values are resolved when they hold items, by identity: the same instance
    // added as a plain source and as a template source is one source, and a template source.
    private readonly HashSet<IProtectedReadOnlyCache> _templateSources = new(ReferenceEqualityComparer.Instance);
    private readonly List<IValueProvider> _valueProviders = [];
    private readonly ResolvedStore _resolved;
    private readonly ConcurrentDictionary<string, IProtectedReadOnlyCache> _plain = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly int _maxResolvedLength = DefaultMaxResolvedLength;
    private long _generation;

    /// <summary>Creates an empty collection.</summary>
    /// <param name="keyRing">Encrypts each resolved value under its current key, and decrypts it under
    /// the version it recorded. Owned by the caller.</param>
    public ResolvingProtectedCacheCollection(IKeyRing keyRing)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        _resolved = new ResolvedStore(keyRing);
    }

    /// <summary>The token that marks an item; <c>${</c>, <c>}</c> and the escape <c>$</c> by default.</summary>
    public ConfigurationItemTokenBase Token { get; init; } = new DefaultToken();

    /// <summary>
    /// The most UTF-8 bytes a resolved value may hold; <see cref="DefaultMaxResolvedLength"/> by
    /// default. A template that resolves to more throws InvalidOperationException on lookup.
    /// </summary>
    public int MaxResolvedLength
    {
        get => _maxResolvedLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxResolvedLength = value;
        }
    }

    /// <summary>
    /// Registers source as an additional lookup source, checked after every source already added -
    /// for names and for the items in templates alike. Its values are never templates: one that
    /// holds <c>${...}</c> is answered exactly as stored, and nothing it names is looked up. Use this
    /// for a source other parties can write to, such as a shared secret store; see
    /// <see cref="AddTemplateSource"/> for one whose values may be templates.
    /// </summary>
    /// <returns>This same collection, for fluent chaining</returns>
    public ResolvingProtectedCacheCollection Add(IProtectedReadOnlyCache source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _sources.Add(source);
        return this;
    }

    /// <summary>
    /// Registers source as an additional lookup source, as <see cref="Add"/> does, whose values are
    /// also templates: a value of its that holds items is resolved on lookup, from every source (this
    /// one included) and then every value provider. A template can name any value the application
    /// can read, so add this way only a source written by parties trusted with every secret in the
    /// collection - the application's own configuration, say - and never a store others can write to.
    /// </summary>
    /// <returns>This same collection, for fluent chaining</returns>
    public ResolvingProtectedCacheCollection AddTemplateSource(IProtectedReadOnlyCache source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _sources.Add(source);
        _templateSources.Add(source);
        return this;
    }

    /// <summary>
    /// Registers a value provider - environment variables, a dictionary - for the items in templates
    /// only, asked after every source and every provider already added. Its values are never answered
    /// by name on their own. A provider that holds its values as strings is no place for secrets.
    /// </summary>
    /// <returns>This same collection, for fluent chaining</returns>
    public ResolvingProtectedCacheCollection AddValueProvider(IValueProvider valueProvider)
    {
        ArgumentNullException.ThrowIfNull(valueProvider);
        _valueProviders.Add(valueProvider);
        return this;
    }

    /// <summary>
    /// Forgets name's resolved value, or which source holds it, so the next lookup reads it again.
    /// </summary>
    /// <returns>True if anything was remembered for name</returns>
    public bool Invalidate(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            _generation++;
            var resolved = _resolved.Remove(StoreKey(name));
            return _plain.TryRemove(name, out _) | resolved;
        }
    }

    /// <summary>Forgets every resolved value, and every source a value was found in.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _generation++;
            _resolved.Clear();
            _plain.Clear();
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            var key = StoreKey(name);
            while (true)
            {
                var written = _resolved.Decrypt(key, result);
                if (written > 0)
                    return written;

                if (Locate(name, out var source) != Location.Resolved)
                    return source?.Decrypt(name, result) ?? 0;
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            var key = StoreKey(name);
            while (true)
            {
                var written = _resolved.Decrypt(key, result);
                if (written > 0)
                    return written;

                if (Locate(name, out var source) != Location.Resolved)
                    return source?.Decrypt(name, result) ?? 0;
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        var key = StoreKey(name);
        while (true)
        {
            if (_resolved.TryGetMaxDecryptedLength(key, out maxLength))
                return true;

            if (Locate(name, out var source) != Location.Resolved)
            {
                maxLength = 0;
                return source is not null && source.TryGetMaxDecryptedLength(name, out maxLength);
            }
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public async ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            var key = StoreKey(name);
            while (true)
            {
                var written = _resolved.Decrypt(key, result.Span);
                if (written > 0)
                    return written;

                var (location, source) = await LocateAsync(name, cancellationToken).ConfigureAwait(false);
                if (location != Location.Resolved)
                    return source is null ? 0 : await source.DecryptAsync(name, result, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public async ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            var key = StoreKey(name);
            while (true)
            {
                var written = _resolved.Decrypt(key, result.Span);
                if (written > 0)
                    return written;

                var (location, source) = await LocateAsync(name, cancellationToken).ConfigureAwait(false);
                if (location != Location.Resolved)
                    return source is null ? 0 : await source.DecryptAsync(name, result, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="global::ConfigurationResolver.Exceptions.ConfigurationKeyException">name's value is a template naming a value nothing has</exception>
    /// <exception cref="InvalidOperationException">name's value resolves to more than <see cref="MaxResolvedLength"/> bytes</exception>
    public async ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
    {
        var key = StoreKey(name);
        while (true)
        {
            if (_resolved.TryGetMaxDecryptedLength(key, out var maxLength))
                return maxLength;

            var (location, source) = await LocateAsync(name, cancellationToken).ConfigureAwait(false);
            if (location != Location.Resolved)
                return source is null ? 0 : await source.GetMaxDecryptedLengthAsync(name, cancellationToken).ConfigureAwait(false);
        }
    }

    private enum Location
    {
        /// <summary>No source holds the name, or its template resolved to nothing.</summary>
        Missing,

        /// <summary>A source holds the name, and its value has no items: that source answers.</summary>
        Source,

        /// <summary>The name's template was resolved: look in the resolved store again. If an
        /// Invalidate or Clear kept the result out of it, the lookup resolves it again.</summary>
        Resolved,
    }

    /// <summary>
    /// Finds name's value outside the resolved store, resolving and caching it on the way when it is a
    /// template.
    /// </summary>
    private Location Locate(string name, out IProtectedReadOnlyCache? source)
    {
        if (_plain.TryGetValue(name, out source))
            return Location.Source;

        var generation = Volatile.Read(ref _generation);
        source = FindSource(name, out var maxLength);
        if (source is null)
            return Location.Missing;

        // A plain source's value is never a template: it isn't even read here, let alone parsed.
        if (!_templateSources.Contains(source))
            return Remember(name, source, generation);

        var template = ReadTemplate(source, name, maxLength, out var length, out var reader);
        if (template is null)
            return Remember(name, source, generation);

        source = null;
        try
        {
            long bound = length;
            foreach (var key in reader!.Keys())
            {
                FindSource(key, out var keyLength);
                bound += keyLength;
            }

            return Resolve(name, template.AsSpan(0, length), reader, bound, generation);
        }
        finally
        {
            ArrayUtility.ZeroMemory(template);
        }
    }

    private async ValueTask<(Location, IProtectedReadOnlyCache?)> LocateAsync(string name, CancellationToken cancellationToken)
    {
        if (_plain.TryGetValue(name, out var source))
            return (Location.Source, source);

        var generation = Volatile.Read(ref _generation);
        (source, var maxLength) = await FindSourceAsync(name, cancellationToken).ConfigureAwait(false);
        if (source is null)
            return (Location.Missing, null);

        // A plain source's value is never a template: it isn't even read here, let alone parsed.
        if (!_templateSources.Contains(source))
            return (Remember(name, source, generation), source);

        // The source has the value in hand now, so reading it doesn't fetch.
        var template = ReadTemplate(source, name, maxLength, out var length, out var reader);
        if (template is null)
            return (Remember(name, source, generation), source);

        try
        {
            long bound = length;
            foreach (var key in reader!.Keys())
                bound += (await FindSourceAsync(key, cancellationToken).ConfigureAwait(false)).MaxLength;

            return (Resolve(name, template.AsSpan(0, length), reader, bound, generation), null);
        }
        finally
        {
            ArrayUtility.ZeroMemory(template);
        }
    }

    // The first source holding name, as ProtectedCacheCollection finds it.
    private IProtectedReadOnlyCache? FindSource(string name, out int maxLength)
    {
        foreach (var source in _sources)
        {
            if (source.TryGetMaxDecryptedLength(name, out maxLength))
                return source;
        }

        maxLength = 0;
        return null;
    }

    private async ValueTask<(IProtectedReadOnlyCache? Source, int MaxLength)> FindSourceAsync(string name, CancellationToken cancellationToken)
    {
        foreach (var source in _sources)
        {
            var maxLength = await source.GetMaxDecryptedLengthAsync(name, cancellationToken).ConfigureAwait(false);
            if (maxLength > 0)
                return (source, maxLength);
        }

        return (null, 0);
    }

    /// <summary>
    /// Reads name's value from source into pinned memory, returning it with a reader that has read its
    /// items - or null, the memory already zeroed, when it holds none.
    /// </summary>
    private byte[]? ReadTemplate(IProtectedReadOnlyCache source, string name, int maxLength, out int length, out ConfigurationItemReader? reader)
    {
        var value = ArrayUtility.AllocatePinned<byte>(maxLength);
        length = source.Decrypt(name, value);
        reader = new ConfigurationItemReader(Token);
        if (reader.ReadKeys(value.AsSpan(0, length)).Count > 0)
            return value;

        ArrayUtility.ZeroMemory(value);
        reader = null;
        return null;
    }

    private Location Remember(string name, IProtectedReadOnlyCache source, long generation)
    {
        lock (_gate)
        {
            if (generation == _generation)
                _plain[name] = source;
        }

        return Location.Source;
    }

    /// <summary>
    /// Resolves template and caches the result under name - unless Invalidate or Clear was called
    /// since generation was read, when the result is dropped for the lookup to resolve again.
    /// </summary>
    private Location Resolve(string name, ReadOnlySpan<byte> template, ConfigurationItemReader reader, long bound, long generation)
    {
        var resolver = new ConfigurationItemResolver(Token, reader,
            _sources.Select(source => (IValueProvider)new ProtectedCacheValueProvider(source)).Concat(_valueProviders));

        // The sources' bounds cover their values; a value provider's can't be known up front, so a
        // value from one may need a larger buffer.
        var capacity = (int)Math.Clamp(bound, 1, _maxResolvedLength);
        while (true)
        {
            var resolved = ArrayUtility.AllocatePinned<byte>(capacity);
            try
            {
                int written;
                try
                {
                    written = resolver.Resolve(template, resolved);
                }
                catch (ArgumentException ex)
                {
                    if (capacity >= _maxResolvedLength)
                        throw new InvalidOperationException($"The value resolves to more than {nameof(MaxResolvedLength)} ({_maxResolvedLength}) bytes.", ex);

                    capacity = (int)Math.Min(2L * capacity, _maxResolvedLength);
                    continue;
                }

                if (written == 0)
                    return Location.Missing;

                lock (_gate)
                {
                    if (generation == _generation)
                        _resolved.Set(StoreKey(name), resolved.AsSpan(0, written));
                    return Location.Resolved;
                }
            }
            finally
            {
                ArrayUtility.ZeroMemory(resolved);
            }
        }
    }

    // The resolved store matches names ignoring ASCII case, as every ProtectedCacheBase does; this
    // collection matches them exactly, as its sources may. So each name is stored under a spelling
    // with no upper-case ASCII: '!' becomes "!!", and an upper-case letter '!' and its lower-case form.
    private static string StoreKey(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!name.AsSpan().ContainsAny("!ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
            return name;

        var key = new StringBuilder(name.Length + 8);
        foreach (var c in name)
        {
            if (c == '!')
                key.Append("!!");
            else if (c is >= 'A' and <= 'Z')
                key.Append('!').Append((char)(c + ('a' - 'A')));
            else
                key.Append(c);
        }

        return key.ToString();
    }

    private static System.Diagnostics.Activity? StartDecryptActivity(string name)
    {
        var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));
        return activity;
    }

    /// <summary>The resolved values, encrypted and bound to their (store-key) names.</summary>
    private sealed class ResolvedStore(IKeyRing keyRing) : ProtectedCacheBase(keyRing)
    {
        public void Set(string key, Span<byte> plaintext) => Data[key] = Encrypt(key, plaintext);

        public bool Remove(string key) => Data.TryRemove(key, out _);

        public void Clear() => Data.Clear();
    }
}
