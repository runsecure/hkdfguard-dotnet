using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <summary>
/// Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background timer,
/// ticking every expirySeconds, proactively reveals the DEK fresh (via
/// keyWrapper.UnwrapAsync(wrapped, ...)) and builds the next AesGcmCryptoSession before the current
/// one expires, then swaps it in - so Encrypt/Decrypt never pay the unwrap cost themselves; only
/// CreateAsync does, once, and awaits it. The replaced session is kept for one more interval before being
/// disposed (zeroing its key), so an operation that captured it just before the swap completes
/// normally. Thread-safe: only CreateAsync and the single background loop ever reveal the key.
/// <para>
/// A refresh re-reveals the <em>same</em> DEK, so it is a periodic re-check that the KEK is still
/// accessible, not a bound on how long the DEK value exists in memory. What happens when that
/// check fails is the refresh-failure policy: by default, <see cref="RefreshFailurePolicy.DefaultMaxRefreshFailures"/>
/// consecutive failures dispose every session (zeroing the DEK) and suspend Encrypt/Decrypt - they
/// throw CryptographicException - until a later refresh succeeds and operation resumes. Passing a
/// null <c>maxRefreshFailures</c> instead keeps the last good session in use indefinitely (fail
/// open).
/// </para>
/// </summary>
public sealed class AesGcmCryptoProvider : ICryptoProvider
{
    /// <summary>
    /// Encryptions after which this provider refuses to encrypt (decryption keeps working): half of
    /// NIST SP 800-38D's 2^32 random-nonce limit, since a per-process counter can't see the other
    /// processes sharing the same key file. The count is per DEK and shared by every provider in
    /// this process that reveals it; a background refresh re-reveals the same key, so it does not
    /// reset the count.
    /// </summary>
    public const long MaxEncryptionsPerKey = EncryptionBudget.DefaultLimit;

    /// <summary>
    /// Encryptions after which an <see cref="EventNames.EncryptionBudgetWarning"/> event is
    /// raised, once, on the encrypt span that crosses it.
    /// </summary>
    public const long EncryptionWarningThreshold = EncryptionBudget.DefaultWarningThreshold;

    private const int KeyLength = 32;
    private const int ExtraAllocationLength = AesGcmCryptoSession.NonceSize + AesGcmCryptoSession.TagSize;
    
    private readonly IKeyWrapper _keyWrapper;
    private readonly EncryptionBudget _budget;
    private readonly int? _maxRefreshFailures;
    private readonly ILogger? _logger;
    private int _consecutiveRefreshFailures;
    private readonly byte[] _wrapped;
    private readonly int _expirySeconds;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _refreshTask;
    private readonly Lock _gate = new();
    private AesGcmCryptoSession? _current;
    // The session a refresh replaced. Encrypt/Decrypt read _current without a lock, so a call that
    // captured the old session just before a swap may still be using it; it's disposed one
    // interval later, on the next swap (or on Dispose), rather than immediately.
    private AesGcmCryptoSession? _retiring;
    private int _disposed;

    // Construction always goes through CreateAsync, so the first key reveal is awaited, never
    // blocked on.
    private AesGcmCryptoProvider(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds, int? maxRefreshFailures,
        EncryptionBudget budget, AesGcmCryptoSession firstSession, ILogger? logger)
    {
        _logger = logger;
        _budget = budget;
        _maxRefreshFailures = maxRefreshFailures;
        _keyWrapper = keyWrapper;
        _wrapped = wrapped;
        _expirySeconds = expirySeconds;
        _current = firstSession;

        _refreshTask = RunRefreshLoopAsync(_cts.Token);
    }

    /// <summary>
    /// Creates a provider: reveals the DEK through <paramref name="keyWrapper"/> (awaited, so a
    /// network-backed key wrapper never blocks a thread) and starts the background refresh.
    /// </summary>
    /// <param name="keyWrapper">Reveals wrapped's DEK - see IKeyWrapper.UnwrapAsync.</param>
    /// <param name="wrapped">The wrapped DEK payload this provider's sessions decrypt. Owned by the
    /// provider from here on; zeroed when it's disposed.</param>
    /// <param name="expirySeconds">How long each session is used before the next background
    /// refresh, 1-300 seconds; also the refresh interval.</param>
    /// <param name="maxRefreshFailures">Consecutive failed background refreshes tolerated before
    /// failing closed (see the class remarks), at least 1. Defaults to
    /// <see cref="RefreshFailurePolicy.DefaultMaxRefreshFailures"/>; pass null to fail open.</param>
    /// <param name="cancellationToken">Cancels the first key reveal.</param>
    /// <param name="logger">Receives an error for every failed background refresh, a critical entry
    /// when key access is suspended, an informational one when it resumes, and a warning when the
    /// key nears its encryption limit. Optional, but without it (or an ActivityListener) none of
    /// these is visible - and under fail-open a revoked KEK goes unnoticed.</param>
    /// <exception cref="ArgumentOutOfRangeException">expirySeconds is not between 1 and 300, or maxRefreshFailures is below 1</exception>
    public static Task<AesGcmCryptoProvider> CreateAsync(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds,
        int? maxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures, CancellationToken cancellationToken = default, ILogger? logger = null)
        => CreateAsync(keyWrapper, wrapped, expirySeconds, maxRefreshFailures, budget: null, cancellationToken, logger);

    internal static Task<AesGcmCryptoProvider> CreateAsync(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds, EncryptionBudget budget)
        => CreateAsync(keyWrapper, wrapped, expirySeconds, null, budget, CancellationToken.None, null);

    /// <param name="budget">The count to draw on; null for the process-wide one for whichever key
    /// is revealed (see EncryptionBudget.For). Tests pass their own.</param>
    internal static async Task<AesGcmCryptoProvider> CreateAsync(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds,
        int? maxRefreshFailures, EncryptionBudget? budget, CancellationToken cancellationToken, ILogger? logger)
    {
        Validate(expirySeconds, maxRefreshFailures);
        // Don't rely on the key wrapper to honour a token that's already cancelled.
        cancellationToken.ThrowIfCancellationRequested();
        var firstSession = await RevealAsync(keyWrapper, wrapped, budget, logger, cancellationToken).ConfigureAwait(false);
        return new AesGcmCryptoProvider(keyWrapper, wrapped, expirySeconds, maxRefreshFailures, firstSession.Budget, firstSession, logger);
    }

    /// <summary>
    /// Checks the arguments of <see cref="CreateAsync(IKeyWrapper, byte[], int, int?, CancellationToken, ILogger?)"/>,
    /// before any key-wrapper call is made.
    /// </summary>
    internal static void Validate(int expirySeconds, int? maxRefreshFailures)
    {
        if (expirySeconds is < 1 or > 300)
            throw new ArgumentOutOfRangeException(nameof(expirySeconds), expirySeconds, "ExpirySeconds must be between 1 and 300.");
        if (maxRefreshFailures is < 1)
            throw new ArgumentOutOfRangeException(nameof(maxRefreshFailures), maxRefreshFailures, "MaxRefreshFailures must be at least 1.");
    }

    /// <summary>The configured refresh-failure policy; null means fail open.</summary>
    public int? MaxRefreshFailures => _maxRefreshFailures;

    private string RefreshFailurePolicyDescription => _maxRefreshFailures is { } max
        ? $"fail closed after {max} consecutive failures"
        : "fail open (the last good key stays in use)";

    /// <summary>
    /// True while this provider has failed closed: its sessions are disposed and every
    /// Encrypt/Decrypt throws, until a background refresh succeeds.
    /// </summary>
    /// <summary>The session in use, for tests; null while suspended or after Dispose.</summary>
    internal AesGcmCryptoSession? CurrentSession => _current;

    public bool KeyAccessSuspended => _current is null && Volatile.Read(ref _disposed) == 0;

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        while (true)
        {
            AesGcmCryptoSession session;
            try
            {
                session = Session;
            }
            catch
            {
                // Suspended or disposed: no session will run its own zeroing, so honour the
                // ICryptoProvider contract here.
                ArrayUtility.ZeroMemory(plaintext);
                throw;
            }

            // Once it starts, the session zeroes plaintext itself, on success and on every failure.
            // False means it was retired and disposed after it was read here, before it started -
            // nothing was touched, so go round again for the session that replaced it. _current is
            // never set to a disposed session, so this ends.
            if (session.TryEncrypt(plaintext, aad, result, out var written))
                return written;
        }
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        // As Encrypt: a session retired between reading it and starting is skipped for the current one.
        while (true)
        {
            if (Session.TryDecrypt(ciphertext, aad, result, out var written))
                return written;
        }
    }

    private AesGcmCryptoSession Session
    {
        get
        {
            var session = _current;
            if (session is not null)
                return session;

            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
            throw new CryptographicException(
                $"Key access is suspended: {_maxRefreshFailures} consecutive attempts to re-reveal the key through the key wrapper failed. Operations resume once a refresh succeeds.");
        }
    }

    /// <summary>Encryptions performed under this provider's key so far - see <see cref="MaxEncryptionsPerKey"/>.</summary>
    public long EncryptionCount => _budget.Count;

    public int GetEncryptedAllocationLength(int length)
        => length + ExtraAllocationLength;

    /// <inheritdoc/>
    /// <remarks>Never negative: input shorter than the nonce and tag can't be valid ciphertext, and
    /// Decrypt rejects it, but a size computed from it must still be a usable buffer length.</remarks>
    public int GetDecryptedAllocationLength(int length)
        => Math.Max(0, length - ExtraAllocationLength);

    // Reveals the DEK through the key wrapper and builds a session around it. Shared by the first
    // reveal (constructor or CreateAsync) and every background refresh.
    // A null budget means the process-wide one for whichever key is revealed.
    private static async Task<AesGcmCryptoSession> RevealAsync(IKeyWrapper keyWrapper, byte[] wrapped,
        EncryptionBudget? budget, ILogger? logger, CancellationToken cancellationToken)
    {
        // Pinned: this array becomes the session's key and lives until the next refresh, across
        // many collections; a movable array could leave unzeroed copies behind when compacted.
        var key = ArrayUtility.AllocatePinned<byte>(KeyLength);
        try
        {
            var written = await keyWrapper.UnwrapAsync(wrapped, key, cancellationToken).ConfigureAwait(false);

            // A wrapper that reveals fewer bytes (e.g. a misconfigured KMS returning a 128-bit data
            // key) would otherwise leave the rest of the key zero and silently weaken every session.
            if (written != KeyLength)
                throw new CryptographicException($"Key wrapper revealed {written} bytes; a {KeyLength}-byte DEK is required.");

            return new AesGcmCryptoSession(key, budget ?? EncryptionBudget.For(key), logger);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
    }

    // The unwrap runs outside _gate (a lock can't span an await) - safe because only the single
    // background loop refreshes once the provider exists.
    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var fresh = await RevealAsync(_keyWrapper, _wrapped, _budget, _logger, cancellationToken).ConfigureAwait(false);

        lock (_gate)
        {
            var outgoing = Interlocked.Exchange(ref _current, fresh);
            var stale = Interlocked.Exchange(ref _retiring, outgoing);
            stale?.Dispose();
        }
    }
    
    private async Task RunRefreshLoopAsync(
        CancellationToken cancellationToken)
    {
        using var timer =
            new PeriodicTimer(TimeSpan.FromSeconds(_expirySeconds));

        try
        {
            // ConfigureAwait(false): this loop starts on whichever thread finished CreateAsync. If
            // that thread has a single-threaded SynchronizationContext (a UI thread, classic
            // ASP.NET) and later calls Dispose, which blocks on this task, a continuation posted
            // back to that context could never run - a deadlock.
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                using var activity =
                    HkdfGuardTelemetry.CryptoProviderAesGcm256
                        .ActivitySource
                        .StartActivity(
                            ActivityNames.CryptoProviderAesGcm256
                                .BackgroundRefresh);

                try
                {
                    await RefreshAsync(cancellationToken).ConfigureAwait(false);
                    var previousFailures = Interlocked.Exchange(ref _consecutiveRefreshFailures, 0);
                    if (previousFailures >= _maxRefreshFailures)
                        _logger?.KeyAccessResumed(previousFailures);
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    ComponentTelemetry
                        .RecordException(activity, ex);

                    var failures = Interlocked.Increment(ref _consecutiveRefreshFailures);
                    _logger?.KeyRefreshFailed(failures, RefreshFailurePolicyDescription, ex);
                    if (failures == _maxRefreshFailures)
                    {
                        SuspendKeyAccess(activity, failures);
                        _logger?.KeyAccessSuspended(failures);
                    }
                }
            }
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            // Shutdown: Dispose cancelled us. Swallow whatever an in-flight refresh threw on the
            // way out (an OperationCanceledException, or e.g. a key wrapper failing because it was
            // cancelled) - faulting this task would make Dispose's Wait throw.
        }
    }

    // Fail closed: zero every revealed copy of the DEK and refuse operations until a refresh
    // succeeds. The next successful RefreshAsync swaps a fresh session in and resumes service.
    private void SuspendKeyAccess(Activity? activity, int failures)
    {
        lock (_gate)
        {
            // Null unless a refresh has succeeded since the last swap.
            Interlocked.Exchange(ref _retiring, null)?.Dispose();

            // Never null here: suspension happens once per failure streak, and a streak only
            // restarts after a successful refresh has put a session back in _current.
            Interlocked.Exchange(ref _current, null)!.Dispose();
        }

        activity?.AddEvent(new ActivityEvent(EventNames.KeyAccessSuspended, tags: new ActivityTagsCollection
        {
            [AttributeNames.ConsecutiveFailures] = failures,
        }));
    }

    /// <summary>
    /// Stops the background refresh - awaiting a refresh already in flight rather than blocking on
    /// it - then zeroes the wrapped payload and every revealed key. Prefer this over Dispose: an
    /// in-flight refresh may be a network call to a KMS. Safe to call more than once.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (!BeginDispose())
            return;

        // Never faults: RunRefreshLoopAsync records per-tick failures and swallows shutdown ones.
        await _refreshTask.ConfigureAwait(false);
        EndDispose();
    }

    /// <summary>
    /// Synchronous <see cref="DisposeAsync"/>, for IDisposable callers: blocks until a refresh
    /// already in flight observes cancellation.
    /// </summary>
    public void Dispose()
    {
        if (!BeginDispose())
            return;

        _refreshTask.Wait();
        EndDispose();
    }

    private bool BeginDispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return false;

        _cts.Cancel();
        ArrayUtility.ZeroMemory(_wrapped);
        return true;
    }

    private void EndDispose()
    {
        _cts.Dispose();

        lock (_gate)
        {
            Interlocked.Exchange(ref _retiring, null)?.Dispose();
            // Null if this provider had already failed closed.
            Interlocked.Exchange(ref _current, null)?.Dispose();
        }
    }
}
