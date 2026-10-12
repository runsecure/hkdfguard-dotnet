using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// Builds a KeyRing from wrapped-DEK files on disk and/or ephemeral keys, suitable for registering
/// as a singleton in a DI container at startup. One IKeyWrapper is shared by every registered key -
/// it's bound only to a KEK (e.g. NativeHkdfKeyWrapperV1's service name), not to any one wrapped
/// payload, so it can reveal any number of different files' DEKs. For each key file, Build asks the
/// ICryptoProviderFactory to Create an ICryptoProvider bound to that file's wrapped bytes; for each
/// ephemeral version, it asks the factory to CreateEphemeral one around a fresh DEK generated (and
/// wrapped) at Build time. Every provider is wrapped in a DataEncryptionKey owned by the ring, and
/// KeyRefreshInterval is passed to the factory as each provider's refresh interval.
/// ServiceName describes this ring's key identity - it's carried on the builder for callers to
/// read back, but is not consumed by Build itself, since the IKeyWrapper already knows what KEK
/// it's bound to. Key files are rotated by deployment, not here: each release brings its own
/// freshly generated key files. Ephemeral keys are rotated here: a ring with any ephemeral key
/// adds a fresh one as its new current version every <see cref="EphemeralKeyRotationInterval"/>
/// (24 hours unless configured otherwise).
/// </summary>
public sealed class KeyRingBuilder
{
    private readonly SortedDictionary<int, string> _keyFiles = [];
    private readonly List<int> _ephemeralVersions = [];
    private IKeyWrapper? _keyWrapper;
    private ICryptoProviderFactory? _cryptoProviderFactory;
    private IEncryptedFormatProvider _formatProvider = new DefaultFormatProvider();
    private ILogger<KeyRing>? _logger;

    /// <summary>How often a ring with ephemeral keys adds a fresh one as its current version, unless configured otherwise.</summary>
    public static readonly TimeSpan DefaultEphemeralKeyRotationInterval = TimeSpan.FromHours(24);

    /// <summary>
    /// Shortest rotation interval <see cref="WithEphemeralKeyRotation"/> accepts. Every rotation
    /// generates a key through the KEK and starts another background refresh loop, so rotating
    /// faster than this buys no security and only loads the KMS.
    /// </summary>
    public static readonly TimeSpan MinEphemeralKeyRotationInterval = TimeSpan.FromHours(1);

    /// <summary>Longest rotation interval <see cref="WithEphemeralKeyRotation"/> accepts - the longest period a timer supports, about 49.7 days.</summary>
    public static readonly TimeSpan MaxEphemeralKeyRotationInterval = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    /// <summary>
    /// How long a superseded ephemeral key stays in the ring for decryption, unless configured
    /// otherwise: values encrypted under it remain readable for at least this long after a rotation
    /// replaced it, then it is disposed (zeroing its DEK) and removed.
    /// </summary>
    public static readonly TimeSpan DefaultEphemeralKeyRetention = TimeSpan.FromHours(24);

    /// <summary>Shortest retention <see cref="WithEphemeralKeyRetention"/> accepts.</summary>
    public static readonly TimeSpan MinEphemeralKeyRetention = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The refresh-failure policy every built provider gets unless configured otherwise: fail
    /// closed after this many consecutive failed refreshes. With KeyRefreshInterval = 60 that is about
    /// three minutes of KEK outage before the key is zeroed.
    /// </summary>
    public const int DefaultMaxRefreshFailures = RefreshFailurePolicy.DefaultMaxRefreshFailures;

    public string? ServiceName { get; private set; }
    public int? KeyRefreshInterval { get; private set; }

    /// <summary>
    /// Consecutive failed refreshes tolerated before a provider fails closed. Defaults to
    /// <see cref="DefaultMaxRefreshFailures"/>; null only after an explicit
    /// <see cref="WithFailOpenOnRefreshFailure"/>.
    /// </summary>
    public int? MaxRefreshFailures { get; private set; } = DefaultMaxRefreshFailures;

    /// <summary>
    /// How often the built ring adds a fresh ephemeral key as its new current version. Defaults to
    /// <see cref="DefaultEphemeralKeyRotationInterval"/>; null only after an explicit
    /// <see cref="WithoutEphemeralKeyRotation"/>. Applies only to a ring with at least one ephemeral
    /// key: a ring of key files alone never rotates, so its key-file version stays current.
    /// </summary>
    public TimeSpan? EphemeralKeyRotationInterval { get; private set; } = DefaultEphemeralKeyRotationInterval;

    /// <summary>
    /// How long a superseded ephemeral key stays registered for decryption after a rotation
    /// replaces it, before the ring disposes and removes it. Defaults to
    /// <see cref="DefaultEphemeralKeyRetention"/>. Only a ring that rotates ever supersedes a key,
    /// so this has no effect without rotation.
    /// </summary>
    public TimeSpan EphemeralKeyRetention { get; private set; } = DefaultEphemeralKeyRetention;

    /// <summary>
    /// Sets how often the built ring rotates its ephemeral encryption key: each interval it
    /// generates a fresh ephemeral key and adds it at CurrentVersion + 1, so every later Encrypt
    /// uses it. Earlier keys stay registered for <see cref="EphemeralKeyRetention"/>, so what they
    /// encrypted still decrypts for that long.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">interval is outside
    /// <see cref="MinEphemeralKeyRotationInterval"/>-<see cref="MaxEphemeralKeyRotationInterval"/></exception>
    public KeyRingBuilder WithEphemeralKeyRotation(TimeSpan interval)
    {
        if (interval < MinEphemeralKeyRotationInterval || interval > MaxEphemeralKeyRotationInterval)
            throw new ArgumentOutOfRangeException(nameof(interval), interval,
                $"The ephemeral key rotation interval must be between {MinEphemeralKeyRotationInterval} and {MaxEphemeralKeyRotationInterval}.");

        EphemeralKeyRotationInterval = interval;
        return this;
    }

    /// <summary>
    /// Turns scheduled ephemeral key rotation off: the ephemeral key built at startup stays current
    /// until the process restarts. A later <see cref="WithEphemeralKeyRotation"/> call replaces this.
    /// </summary>
    public KeyRingBuilder WithoutEphemeralKeyRotation()
    {
        EphemeralKeyRotationInterval = null;
        return this;
    }

    // Tests only: any positive interval, so rotation can be observed in milliseconds.
    internal KeyRingBuilder WithEphemeralKeyRotationForTesting(TimeSpan interval)
    {
        EphemeralKeyRotationInterval = interval;
        return this;
    }

    /// <summary>
    /// Sets how long a superseded ephemeral key stays registered for decryption after a rotation
    /// replaces it. Once that long has passed - checked at the next rotation - the key is disposed,
    /// zeroing its DEK, and removed: a value encrypted under it then fails with
    /// KeyNotFoundException. Keys read from key files are never retired. Not calling this keeps
    /// <see cref="DefaultEphemeralKeyRetention"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">retention is below <see cref="MinEphemeralKeyRetention"/></exception>
    public KeyRingBuilder WithEphemeralKeyRetention(TimeSpan retention)
    {
        if (retention < MinEphemeralKeyRetention)
            throw new ArgumentOutOfRangeException(nameof(retention), retention,
                $"The ephemeral key retention must be at least {MinEphemeralKeyRetention}.");

        EphemeralKeyRetention = retention;
        return this;
    }

    // Tests only: any positive retention, so retirement can be observed in milliseconds.
    internal KeyRingBuilder WithEphemeralKeyRetentionForTesting(TimeSpan retention)
    {
        EphemeralKeyRetention = retention;
        return this;
    }

    /// <summary>
    /// Receives an informational entry for every ephemeral key rotation and an error for every
    /// failed one. Optional.
    /// </summary>
    public KeyRingBuilder WithLogger(ILogger<KeyRing>? logger)
    {
        _logger = logger;
        return this;
    }

    /// <summary>
    /// The service name identifying this ring's KEK to the native KMS library: 1-128 ASCII
    /// letters, digits or '.', not starting with '.' and without ".." (see ServiceNames).
    /// </summary>
    /// <exception cref="ArgumentNullException">serviceName is null</exception>
    /// <exception cref="ArgumentException">serviceName breaks a ServiceNames rule</exception>
    public KeyRingBuilder WithServiceName(string serviceName)
    {
        ServiceNames.ThrowIfInvalid(serviceName, nameof(serviceName));
        ServiceName = serviceName;
        return this;
    }

    /// <summary>
    /// How often, in seconds, each key is re-revealed through the KEK to confirm the KEK is still
    /// available - the same 1-300 range AesGcmCryptoProvider accepts, so a bad value fails here,
    /// not at Build. A revocation check, not a limit on how long the DEK stays in memory: the same
    /// DEK is revealed each time, and it stays in memory until the ring is disposed. Together with
    /// <see cref="MaxRefreshFailures"/> it sets how quickly a revoked KEK stops a running process -
    /// about MaxRefreshFailures × KeyRefreshInterval.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">keyRefreshInterval is not between 1 and 300</exception>
    public KeyRingBuilder WithKeyRefreshInterval(int keyRefreshInterval)
    {
        if (keyRefreshInterval is < 1 or > 300)
            throw new ArgumentOutOfRangeException(nameof(keyRefreshInterval), keyRefreshInterval, "KeyRefreshInterval must be between 1 and 300 seconds.");

        KeyRefreshInterval = keyRefreshInterval;
        return this;
    }

    /// <summary>
    /// The refresh-failure policy handed to every provider Build creates: after this many
    /// consecutive failed attempts to re-reveal a key through the IKeyWrapper, that key's
    /// provider fails closed - zeroes its DEK and throws on every operation until a refresh
    /// succeeds. Not calling this keeps <see cref="DefaultMaxRefreshFailures"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">maxRefreshFailures is below 1</exception>
    public KeyRingBuilder WithMaxRefreshFailures(int maxRefreshFailures)
    {
        if (maxRefreshFailures < 1)
            throw new ArgumentOutOfRangeException(nameof(maxRefreshFailures), maxRefreshFailures, "MaxRefreshFailures must be at least 1.");

        MaxRefreshFailures = maxRefreshFailures;
        return this;
    }

    /// <summary>
    /// Opts out of failing closed: every provider keeps using its last good key no matter how
    /// many refreshes fail, so revoking or losing the KEK never stops a running process. Choose
    /// this only when availability matters more than revocation taking effect, and pass a logger
    /// to the crypto provider factory - each failed refresh is then logged as an error, which is
    /// the only sign the KEK is gone. A later <see cref="WithMaxRefreshFailures"/> call replaces it.
    /// </summary>
    public KeyRingBuilder WithFailOpenOnRefreshFailure()
    {
        MaxRefreshFailures = null;
        return this;
    }

    /// <summary>
    /// Supplies the IKeyWrapper shared by every registered key file when Build runs.
    /// </summary>
    public KeyRingBuilder WithKeyWrapper(IKeyWrapper keyWrapper)
    {
        _keyWrapper = keyWrapper;
        return this;
    }

    /// <summary>
    /// Supplies the ICryptoProviderFactory Build uses to create each key's ICryptoProvider - Create
    /// once per key file (with the shared IKeyWrapper and that file's wrapped bytes), CreateEphemeral
    /// once per ephemeral version - e.g. <c>new AesGcmCryptoProviderFactory()</c>.
    /// </summary>
    public KeyRingBuilder WithCryptoProviderFactory(ICryptoProviderFactory cryptoProviderFactory)
    {
        _cryptoProviderFactory = cryptoProviderFactory;
        return this;
    }

    /// <summary>
    /// Overrides the IEncryptedFormatProvider the built KeyRing uses for CreateProtector.
    /// Defaults to DefaultFormatProvider.
    /// </summary>
    public KeyRingBuilder WithFormatProvider(IEncryptedFormatProvider formatProvider)
    {
        _formatProvider = formatProvider;
        return this;
    }

    /// <summary>
    /// Registers a version whose wrapped DEK will be read from pathToFile when Build runs. The
    /// highest version registered across every WithKeyFile call intrinsically becomes the built
    /// KeyRing's CurrentVersion.
    /// </summary>
    /// <param name="version">The KeyRing version to register this key under</param>
    /// <param name="pathToFile">Path to this version's wrapped DEK file</param>
    public KeyRingBuilder WithKeyFile(int version, string pathToFile)
    {
        _keyFiles.Add(version, pathToFile);
        return this;
    }

    /// <summary>
    /// Registers a version whose DEK is generated fresh at Build time (via
    /// ICryptoProviderFactory.CreateEphemeralAsync) and never written to or read from disk - it lives
    /// only as long as the built KeyRing. The highest version registered across every
    /// WithKeyFile/WithEphemeralKey call intrinsically becomes the built KeyRing's CurrentVersion.
    /// </summary>
    /// <param name="version">The KeyRing version to register this key under</param>
    public KeyRingBuilder WithEphemeralKey(int version)
    {
        _ephemeralVersions.Add(version);
        return this;
    }

    /// <summary>
    /// Reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
    /// returns a populated KeyRing - awaiting every key-wrapper call rather than blocking on it.
    /// </summary>
    /// <param name="cancellationToken">Cancels reading key files and revealing keys; anything
    /// already created is disposed.</param>
    /// <exception cref="InvalidOperationException">No key wrapper, no crypto provider factory, no key refresh interval, or no key files/ephemeral keys were configured</exception>
    public async Task<KeyRing> BuildAsync(CancellationToken cancellationToken = default)
    {
        if (_keyWrapper is null)
            throw new InvalidOperationException("A key wrapper is required - call WithKeyWrapper first.");

        if (_cryptoProviderFactory is null)
            throw new InvalidOperationException("A crypto provider factory is required - call WithCryptoProviderFactory first.");

        if (_keyFiles.Count == 0 && _ephemeralVersions.Count == 0)
            throw new InvalidOperationException("At least one key file or ephemeral key is required - call WithKeyFile or WithEphemeralKey first.");

        if (KeyRefreshInterval is null)
            throw new InvalidOperationException("A key refresh interval is required - call WithKeyRefreshInterval first.");

        // If anything fails partway (unreadable file, unwrap failure, duplicate version), dispose
        // every provider created so far - each runs a background refresh holding a revealed key.
        var ring = new KeyRing(_formatProvider);
        try
        {
            foreach (var (version, path) in _keyFiles)
            {
                var wrapped = await ReadKeyFileAsync(path, cancellationToken).ConfigureAwait(false);
                var provider = await _cryptoProviderFactory
                    .CreateAsync(_keyWrapper, wrapped, KeyRefreshInterval.Value, MaxRefreshFailures, cancellationToken)
                    .ConfigureAwait(false);
                await AddOwnedAsync(ring, version, provider).ConfigureAwait(false);
            }

            foreach (var version in _ephemeralVersions)
            {
                var provider = await _cryptoProviderFactory
                    .CreateEphemeralAsync(_keyWrapper, KeyRefreshInterval.Value, MaxRefreshFailures, cancellationToken)
                    .ConfigureAwait(false);
                await AddOwnedAsync(ring, version, provider).ConfigureAwait(false);
            }

            if (_ephemeralVersions.Count > 0 && EphemeralKeyRotationInterval is { } interval)
            {
                // Each rotation creates its key exactly as an ephemeral version above was created.
                var factory = _cryptoProviderFactory;
                var wrapper = _keyWrapper;
                var refreshInterval = KeyRefreshInterval.Value;
                var maxRefreshFailures = MaxRefreshFailures;
                ring.ConfigureEphemeralKeyRetention(EphemeralKeyRetention, _ephemeralVersions);
                ring.StartEphemeralKeyRotation(interval, async ct =>
                    new DataEncryptionKey(await factory.CreateEphemeralAsync(wrapper, refreshInterval, maxRefreshFailures, ct).ConfigureAwait(false)),
                    _logger);
            }

            return ring;
        }
        catch
        {
            await ring.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Reads a wrapped DEK, refusing an empty file or one over WrappedKeyLimits.MaxBytes. Never
    /// reads more than one byte past the limit, whatever the file's size - so a wrong path (a log,
    /// a device) or a file still growing can't make startup allocate an unbounded buffer.
    /// </summary>
    /// <exception cref="InvalidDataException">The file is empty or larger than the limit</exception>
    private static async Task<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        });

        var buffer = new byte[WrappedKeyLimits.MaxBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length
               && (read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false)) > 0)
            total += read;

        if (total == 0)
            throw new InvalidDataException($"Key file '{path}' is empty.");
        if (total > WrappedKeyLimits.MaxBytes)
            throw new InvalidDataException(
                $"Key file '{path}' is larger than {WrappedKeyLimits.MaxBytes} bytes (WrappedKeyLimits.MaxBytes); a wrapped key never is.");

        return buffer[..total];
    }

    private static async Task AddOwnedAsync(KeyRing ring, int version, ICryptoProvider provider)
    {
        var key = new DataEncryptionKey(provider);
        try
        {
            ring.Add(version, key);
        }
        catch
        {
            await key.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
