using System.Collections.Concurrent;
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
/// Adds it at CurrentVersion + 1, so it becomes current and every later Encrypt uses it. Nothing
/// is removed - earlier keys stay registered so everything already encrypted under them still
/// decrypts. Dispose stops the rotation before disposing any key.
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

    /// <summary>
    /// How often this ring adds a fresh ephemeral key as its new current version; null when it
    /// doesn't rotate (no ephemeral keys, or rotation turned off).
    /// </summary>
    public TimeSpan? EphemeralKeyRotationInterval { get; private set; }

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
    /// One rotation: create a fresh key and Add it at CurrentVersion + 1. A failure - the key
    /// wrapper unavailable, the next version already taken, versions exhausted - is recorded and
    /// logged, the current key stays in use, and the next interval tries again.
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
            activity?.SetTag(AttributeNames.KeyVersion, current + 1);
            logger?.EphemeralKeyRotated(current + 1);
            return true;
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
    /// <exception cref="KeyNotFoundException">No key is registered for this version</exception>
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
    /// <param name="name">Used as this protector's Additional Auth Data on every Encrypt/Decrypt</param>
    /// <exception cref="ArgumentException">name is null or empty - an empty purpose binds nothing,
    /// and would match anything else encrypted without AAD (e.g. ProtectedCache's entries)</exception>
    public IDataProtector CreateProtector(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
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
