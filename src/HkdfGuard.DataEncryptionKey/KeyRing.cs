using System.Collections.Concurrent;
using System.Diagnostics;
using HkdfGuard.DataEncryptionKey.Protector;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// Tracks IDataEncryptionKey instances by version for highly concurrent workloads (thousands of
/// operations per second). Get is served straight off a ConcurrentDictionary, so the hot read
/// path never blocks - no telemetry on that path either, only on a Get miss, since that's the
/// exceptional case and startup overhead there is irrelevant. Add is serialized through a
/// SemaphoreSlim - key registration only happens at startup/rotation, not per-operation, so the
/// gate (and its telemetry) costs nothing where it matters and keeps the door open for an
/// async-loaded Add later (SemaphoreSlim supports WaitAsync; lock does not).
///
/// The ring tracks its own current version intrinsically: whichever registered version number is
/// highest becomes CurrentVersion, automatically, the moment it's Added - there is no separate
/// call to designate one, so it can never fall out of sync with what's actually registered.
///
/// The ring owns every key added to it: Dispose disposes each one that is IDisposable (e.g.
/// DataEncryptionKey, which in turn stops its provider's background refresh and zeroes its key).
///
/// A ring built with ephemeral keys also rotates its encryption key on a schedule (see
/// KeyRingBuilder.WithEphemeralKeyRotation): every interval it generates a fresh ephemeral key and
/// Adds it at CurrentVersion + 1, so it becomes current and every later Encrypt uses it. A
/// superseded ephemeral key stays registered for <see cref="EphemeralKeyRetention"/>, so values
/// encrypted under it still decrypt for that long; then the next rotation disposes it (zeroing its
/// DEK and stopping its background refresh) and removes it, so a ring never accumulates keys
/// without bound. Keys read from key files are never retired. Dispose stops the rotation before
/// disposing any key.
/// </summary>
public sealed class KeyRing(IEncryptedFormatProvider formatProvider) : IKeyRing, IDisposable, IAsyncDisposable
{
    // A long, so the "no key yet" sentinel lies outside the int range: every int, including
    // int.MinValue, is a usable version. Read and written atomically through Volatile.
    private const long NoCurrentVersion = long.MinValue;

    private readonly ConcurrentDictionary<int, IDataEncryptionKey> _keysByVersion = new();
    private readonly SemaphoreSlim _addGate = new(1, 1);
    private long _currentVersion = NoCurrentVersion;
    private int _disposed;
    private CancellationTokenSource? _rotationCts;
    private Task? _rotationTask;

    // Retention state. Only the single rotation loop (or a test driving one rotation at a time)
    // touches these after construction, so they need no synchronization of their own.
    private readonly HashSet<int> _ephemeralVersions = [];
    // Version -> the Stopwatch timestamp at which a rotation first saw it superseded. Monotonic,
    // so a wall-clock jump can neither retire a key early nor keep it forever.
    private readonly Dictionary<int, long> _supersededAt = [];

    /// <summary>
    /// How often this ring adds a fresh ephemeral key as its new current version; null when it
    /// doesn't rotate (no ephemeral keys, or rotation turned off).
    /// </summary>
    public TimeSpan? EphemeralKeyRotationInterval { get; private set; }

    /// <summary>
    /// How long a superseded ephemeral key stays registered before a rotation retires it; null
    /// when this ring doesn't rotate, since only a rotation supersedes a key.
    /// </summary>
    public TimeSpan? EphemeralKeyRetention { get; private set; }

    /// <summary>
    /// Enables retirement: <paramref name="ephemeralVersions"/> are the versions eligible for it
    /// (every version a later rotation adds is too), and <paramref name="retention"/> is how long a
    /// superseded one is kept. Called once, by KeyRingBuilder.BuildAsync, before rotation starts.
    /// </summary>
    internal void ConfigureEphemeralKeyRetention(TimeSpan retention, IEnumerable<int> ephemeralVersions)
    {
        EphemeralKeyRetention = retention;
        foreach (var version in ephemeralVersions)
            _ephemeralVersions.Add(version);
    }

    /// <summary>
    /// Starts the scheduled rotation: every <paramref name="interval"/>, create a key with
    /// <paramref name="createKey"/> and Add it at CurrentVersion + 1. Called once, by
    /// KeyRingBuilder.BuildAsync.
    /// </summary>
    internal void StartEphemeralKeyRotation(TimeSpan interval,
        Func<CancellationToken, ValueTask<IDataEncryptionKey>> createKey, ILogger? logger)
    {
        EphemeralKeyRotationInterval = interval;
        _rotationCts = new CancellationTokenSource();
        _rotationTask = RunEphemeralKeyRotationAsync(interval, createKey, logger, _rotationCts.Token);
    }

    private async Task RunEphemeralKeyRotationAsync(TimeSpan interval,
        Func<CancellationToken, ValueTask<IDataEncryptionKey>> createKey, ILogger? logger, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            // ConfigureAwait(false) throughout: Dispose blocks on this task, so it must never need
            // the thread that built the ring (see AesGcmCryptoProvider's refresh loop).
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                await RotateEphemeralKeyAsync(createKey, logger, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            // Dispose stopped the rotation. Swallow whatever an in-flight rotation threw on the way
            // out (a cancellation, or a key wrapper failing because it was cancelled) - faulting
            // this task would make Dispose throw.
        }
    }

    /// <summary>
    /// One rotation: create a fresh key and Add it at CurrentVersion + 1, then retire every
    /// ephemeral key whose retention has run out. A failure - the key wrapper unavailable, the next
    /// version already taken, versions exhausted - is recorded and logged, the current key stays in
    /// use, and the next interval tries again.
    /// </summary>
    /// <returns>True if a new key became current.</returns>
    internal async Task<bool> RotateEphemeralKeyAsync(Func<CancellationToken, ValueTask<IDataEncryptionKey>> createKey,
        ILogger? logger, CancellationToken cancellationToken)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyRingRotateEphemeral);

        var current = CurrentVersion;
        if (current == int.MaxValue)
        {
            var exhausted = new InvalidOperationException(
                $"Version {int.MaxValue} is current, so there is no higher version to rotate to; the current key stays in use.");
            ComponentTelemetry.RecordException(activity, exhausted);
            logger?.EphemeralKeyRotationFailed(current, exhausted);
            return false;
        }

        IDataEncryptionKey? key = null;
        try
        {
            key = await createKey(cancellationToken).ConfigureAwait(false);
            Add(current + 1, key);
            _ephemeralVersions.Add(current + 1);
            activity?.SetTag(AttributeNames.KeyVersion, current + 1);
            logger?.EphemeralKeyRotated(current + 1);
        }
        catch (Exception ex)
        {
            // Not added, so not owned by the ring: release its revealed key here, on every path.
            if (key is IAsyncDisposable asyncDisposable)
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);

            if (cancellationToken.IsCancellationRequested)
                throw;

            ComponentTelemetry.RecordException(activity, ex);
            logger?.EphemeralKeyRotationFailed(current, ex);
            return false;
        }

        await RetireSupersededEphemeralKeysAsync(Stopwatch.GetTimestamp(), logger, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Retires every ephemeral key that stopped being current at least <see cref="EphemeralKeyRetention"/>
    /// ago: removes it from the ring, so Get/TryGet no longer find it, and disposes it, zeroing its
    /// DEK and stopping its background refresh. An ephemeral key is first seen as superseded by the
    /// rotation that follows the one replacing it, so it is kept for at least the retention - never
    /// less. Does nothing on a ring without retention configured. Key-file versions are never
    /// touched.
    /// </summary>
    /// <param name="now">The current Stopwatch timestamp; a parameter so tests can move time.</param>
    internal async Task RetireSupersededEphemeralKeysAsync(long now, ILogger? logger, CancellationToken cancellationToken)
    {
        if (EphemeralKeyRetention is not { } retention)
            return;

        var current = CurrentVersion;
        foreach (var version in _ephemeralVersions)
        {
            if (version != current && !_supersededAt.ContainsKey(version))
                _supersededAt[version] = now;
        }

        foreach (var (version, supersededAt) in _supersededAt.ToArray())
        {
            if (version == current || Stopwatch.GetElapsedTime(supersededAt, now) < retention)
                continue;

            _supersededAt.Remove(version);
            _ephemeralVersions.Remove(version);
            if (!_keysByVersion.TryRemove(version, out var key))
                continue;

            try
            {
                if (key is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                else
                    (key as IDisposable)?.Dispose();

                logger?.EphemeralKeyRetired(version);
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                // Already out of the ring; a failure to release it must not stop the rotation loop.
                logger?.EphemeralKeyRetirementFailed(version, ex);
            }
        }
    }

    // Stops the rotation loop and waits for a rotation in flight, before any key is disposed - so
    // a key can't be added to a ring that is being torn down.
    private async ValueTask StopEphemeralKeyRotationAsync()
    {
        if (_rotationCts is null)
            return;

        await _rotationCts.CancelAsync().ConfigureAwait(false);
        await _rotationTask!.ConfigureAwait(false);
        _rotationCts.Dispose();
    }

    /// <summary>
    /// The highest version registered so far - what Encrypt-side operations (e.g.
    /// DataProtector.Encrypt) protect new data with.
    /// </summary>
    /// <exception cref="InvalidOperationException">No key has been added yet</exception>
    public int CurrentVersion
    {
        get
        {
            var current = Volatile.Read(ref _currentVersion);
            return current == NoCurrentVersion ? throw new InvalidOperationException("No current version has been set. Add a key first.") : (int)current;
        }
    }

    /// <summary>
    /// Registers a key for the given version. If version is higher than every version registered
    /// so far, it intrinsically becomes the new CurrentVersion. On success the ring takes
    /// ownership of <paramref name="key"/>; if Add throws, ownership stays with the caller.
    /// </summary>
    /// <param name="version">The key version to register</param>
    /// <param name="key">The IDataEncryptionKey for this version</param>
    /// <exception cref="ArgumentException">A key for this version is already registered</exception>
    /// <exception cref="ObjectDisposedException">The ring has been disposed</exception>
    public void Add(int version, IDataEncryptionKey key)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyRingAdd);

        _addGate.Wait();
        try
        {
            if (!_keysByVersion.TryAdd(version, key))
                throw new ArgumentException($"A key for version {version} is already registered.", nameof(version));

            var current = Volatile.Read(ref _currentVersion);
            var becameCurrent = current == NoCurrentVersion || version > current;
            if (becameCurrent)
                Volatile.Write(ref _currentVersion, version);

            if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
                HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyRingAdd,
                    (AttributeNames.KeyVersion, version), (AttributeNames.KeyRingBecameCurrent, becameCurrent));
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
        finally
        {
            _addGate.Release();
        }
    }

    /// <summary>
    /// Retrieves the key registered for the given version
    /// </summary>
    /// <param name="version">The key version to retrieve</param>
    /// <returns>The registered IDataEncryptionKey</returns>
    /// <exception cref="KeyNotFoundException">No key is registered for this version: it was never
    /// added, or it was a superseded ephemeral key whose retention ran out and has been retired</exception>
    public IDataEncryptionKey Get(int version)
    {
        if (_keysByVersion.TryGetValue(version, out var key))
            return key;

        var notFound = new KeyNotFoundException($"No key is registered for version {version}.");
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyRingGet);
        ComponentTelemetry.RecordException(activity, notFound);
        throw notFound;
    }

    /// <summary>
    /// Attempts to retrieve the key registered for the given version without throwing - for the
    /// high-frequency hot path, where exception overhead (and telemetry) on a routine miss is
    /// unacceptable.
    /// </summary>
    /// <param name="version">The key version to retrieve</param>
    /// <param name="key">The registered IDataEncryptionKey, if found</param>
    /// <returns>True if a key was registered for this version</returns>
    public bool TryGet(int version, out IDataEncryptionKey? key)
        => _keysByVersion.TryGetValue(version, out key);

    /// <summary>
    /// Retrieves CurrentVersion together with its IDataEncryptionKey atomically - what
    /// Encrypt-side operations (e.g. DataProtector.Encrypt) resolve fresh on every call, so they
    /// always reflect the latest rotation rather than a version captured once at construction.
    /// </summary>
    /// <returns>The current version and its registered IDataEncryptionKey</returns>
    /// <exception cref="InvalidOperationException">No key has been added yet</exception>
    public (int Version, IDataEncryptionKey Key) GetCurrent()
    {
        try
        {
            var version = CurrentVersion;
            return (version, Get(version));
        }
        catch (InvalidOperationException ex)
        {
            using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyRingGetCurrent);
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>
    /// Creates an IDataProtector bound to this KeyRing - the only way to obtain one, since
    /// DataProtector's constructor is internal to this assembly. Encrypt resolves CurrentVersion
    /// fresh via GetCurrent on every call (not a version captured once here), and formats/parses
    /// via the IEncryptedFormatProvider this ring was constructed with.
    /// </summary>
    /// <param name="name">Used as this protector's Additional Auth Data on every Encrypt/Decrypt.
    /// ProtectedConfigurationPurpose.For(key) names the protector ProtectedConfigurationRoot reads
    /// that configuration key with, which is how pipeline-protected values decrypt; that sharing is
    /// intended.</param>
    /// <exception cref="ArgumentException">name is null or empty - an empty purpose binds nothing,
    /// and would match anything else encrypted without AAD - or starts with
    /// ProtectedCacheBase.AadPrefix, whose AADs are ProtectedCache's alone: a protector named that
    /// way could decrypt cache entries, and produce values a cache would accept</exception>
    public IDataProtector CreateProtector(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.StartsWith(ProtectedCacheBase.AadPrefix, StringComparison.Ordinal))
            throw new ArgumentException(
                $"Protector names starting with '{ProtectedCacheBase.AadPrefix}' are reserved for ProtectedCache's entries.", nameof(name));

        return new DataProtector(name, this, formatProvider);
    }

    /// <summary>
    /// Disposes every registered key - awaiting IAsyncDisposable ones, so each provider's
    /// background refresh is stopped without blocking a thread. Safe to call more than once; keys
    /// stay registered, so a later operation fails with the key's own ObjectDisposedException.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;

        await StopEphemeralKeyRotationAsync().ConfigureAwait(false);
        await _addGate.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach (var key in _keysByVersion.Values)
            {
                if (key is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                else
                    (key as IDisposable)?.Dispose();
            }
        }
        finally
        {
            _addGate.Release();
            _addGate.Dispose();
        }
    }

    /// <summary>
    /// Synchronous <see cref="DisposeAsync"/>, for IDisposable callers: blocks while each key's
    /// provider stops its background refresh. Prefer DisposeAsync.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;

        StopEphemeralKeyRotationAsync().AsTask().GetAwaiter().GetResult();
        _addGate.Wait();
        try
        {
            foreach (var key in _keysByVersion.Values)
                (key as IDisposable)?.Dispose();
        }
        finally
        {
            _addGate.Release();
            _addGate.Dispose();
        }
    }
}
