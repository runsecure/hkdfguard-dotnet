using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// Scheduled ephemeral key rotation: a ring with ephemeral keys adds a fresh one at
/// CurrentVersion + 1 every interval, keeps each superseded key for decryption until its retention
/// runs out and then retires it, and stops rotating when disposed.
/// </summary>
public class EphemeralKeyRotationTests
{
    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(150);

    private static KeyRingBuilder Builder(ICryptoProviderFactory factory) => new KeyRingBuilder()
        .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
        .WithCryptoProviderFactory(factory)
        .WithCachedKeyExpiry(60);

    private static string EncryptedVersion(string formatted) => formatted.Split("::")[1];

    // --- Builder configuration ---------------------------------------------------------------

    [Fact]
    public void Rotation_DefaultsToEveryTwentyFourHours()
    {
        Assert.Equal(TimeSpan.FromHours(24), KeyRingBuilder.DefaultEphemeralKeyRotationInterval);
        Assert.Equal(KeyRingBuilder.DefaultEphemeralKeyRotationInterval, new KeyRingBuilder().EphemeralKeyRotationInterval);
    }

    [Theory]
    [InlineData(1)]       // the minimum, one hour
    [InlineData(6)]
    [InlineData(24 * 7)]
    public void WithEphemeralKeyRotation_AcceptsTheRange(int hours)
    {
        var builder = new KeyRingBuilder();

        Assert.Same(builder, builder.WithEphemeralKeyRotation(TimeSpan.FromHours(hours)));
        Assert.Equal(TimeSpan.FromHours(hours), builder.EphemeralKeyRotationInterval);
    }

    [Fact]
    public void WithEphemeralKeyRotation_NeverAcceptsLessThanAnHour()
    {
        Assert.Equal(TimeSpan.FromHours(1), KeyRingBuilder.MinEphemeralKeyRotationInterval);

        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRotation(TimeSpan.FromMinutes(59)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRotation(TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRotation(TimeSpan.Zero));
    }

    [Fact]
    public void WithEphemeralKeyRotation_AcceptsTheMaximum_AndRefusesBeyondIt()
    {
        new KeyRingBuilder().WithEphemeralKeyRotation(KeyRingBuilder.MaxEphemeralKeyRotationInterval);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new KeyRingBuilder().WithEphemeralKeyRotation(KeyRingBuilder.MaxEphemeralKeyRotationInterval + TimeSpan.FromMilliseconds(1)));
    }

    [Fact]
    public void Retention_DefaultsToTwentyFourHours()
    {
        Assert.Equal(TimeSpan.FromHours(24), KeyRingBuilder.DefaultEphemeralKeyRetention);
        Assert.Equal(KeyRingBuilder.DefaultEphemeralKeyRetention, new KeyRingBuilder().EphemeralKeyRetention);
    }

    [Fact]
    public void WithEphemeralKeyRetention_AcceptsFromOneMinuteUp_AndRefusesLess()
    {
        var builder = new KeyRingBuilder();

        Assert.Same(builder, builder.WithEphemeralKeyRetention(KeyRingBuilder.MinEphemeralKeyRetention));
        Assert.Equal(TimeSpan.FromMinutes(1), builder.EphemeralKeyRetention);
        builder.WithEphemeralKeyRetention(TimeSpan.FromDays(30));
        Assert.Equal(TimeSpan.FromDays(30), builder.EphemeralKeyRetention);

        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRetention(TimeSpan.FromSeconds(59)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRetention(TimeSpan.Zero));
    }

    [Fact]
    public void WithoutEphemeralKeyRotation_TurnsItOff_AndALaterWithTurnsItBackOn()
    {
        var builder = new KeyRingBuilder();

        Assert.Same(builder, builder.WithoutEphemeralKeyRotation());
        Assert.Null(builder.EphemeralKeyRotationInterval);

        builder.WithEphemeralKeyRotation(TimeSpan.FromHours(6));
        Assert.Equal(TimeSpan.FromHours(6), builder.EphemeralKeyRotationInterval);
    }

    // --- Rotation behaviour ------------------------------------------------------------------

    [Fact]
    public async Task ARingWithAnEphemeralKey_AddsAFreshCurrentVersionEachInterval_AndOldValuesStillDecrypt()
    {
        var logger = new RecordingLogger<KeyRing>();
        await using var ring = await Builder(new AesGcmCryptoProviderFactory())
            .WithEphemeralKey(1)
            .WithEphemeralKeyRotationForTesting(Fast)
            .WithLogger(logger)
            .BuildAsync();
        var protector = ring.CreateProtector("rotation");
        var underV1 = protector.Encrypt("written under v1");
        Assert.Equal(Fast, ring.EphemeralKeyRotationInterval);

        await Task.Delay(Fast * 4);

        Assert.True(ring.CurrentVersion >= 3, $"CurrentVersion is {ring.CurrentVersion}");
        var current = ring.CurrentVersion;
        var underCurrent = protector.Encrypt("written under the current key");
        Assert.Equal($"v{current}", EncryptedVersion(underCurrent));
        Assert.Equal("v1", EncryptedVersion(underV1));

        var result = new char[64];
        Assert.Equal("written under v1", new string(result, 0, protector.Decrypt(underV1, result)));
        Assert.Contains(logger.Entries, e => e.EventId == 6 && e.Level == LogLevel.Information);
    }

    [Fact]
    public async Task ARingOfKeyFilesOnly_NeverRotates()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, "wrapped"u8.ToArray());
            var factory = new RecordingCryptoProviderFactory();
            await using var ring = await Builder(factory)
                .WithKeyFile(4, path)
                .WithEphemeralKeyRotationForTesting(Fast)
                .BuildAsync();

            await Task.Delay(Fast * 3);

            Assert.Null(ring.EphemeralKeyRotationInterval);
            Assert.Equal(4, ring.CurrentVersion);
            Assert.Empty(factory.CreateEphemeralExpirySecondsCalls);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task WithRotationTurnedOff_TheStartupEphemeralKeyStaysCurrent()
    {
        var factory = new RecordingCryptoProviderFactory();
        await using var ring = await Builder(factory).WithEphemeralKey(1).WithoutEphemeralKeyRotation().BuildAsync();

        await Task.Delay(Fast * 3);

        Assert.Null(ring.EphemeralKeyRotationInterval);
        Assert.Equal(1, ring.CurrentVersion);
        Assert.Single(factory.CreateEphemeralExpirySecondsCalls);
    }

    [Fact]
    public async Task RotatedKeys_AreCreatedWithTheRingsExpiryAndRefreshPolicy()
    {
        var factory = new RecordingCryptoProviderFactory();
        await using var ring = await Builder(factory)
            .WithMaxRefreshFailures(7)
            .WithEphemeralKey(1)
            .WithEphemeralKeyRotationForTesting(Fast)
            .BuildAsync();

        await Task.Delay(Fast * 3);

        Assert.True(factory.CreateEphemeralExpirySecondsCalls.Count >= 2);
        Assert.All(factory.CreateEphemeralExpirySecondsCalls, e => Assert.Equal(60, e));
        Assert.All(factory.MaxRefreshFailuresCalls, m => Assert.Equal(7, m));
    }

    [Fact]
    public async Task AFailedRotation_KeepsTheCurrentKey_LogsAnError_AndTheNextIntervalSucceeds()
    {
        var logger = new RecordingLogger<KeyRing>();
        var factory = new FlakyFactory { FailuresBeforeSuccess = 1 };
        await using var ring = await Builder(factory)
            .WithEphemeralKey(1)
            .WithEphemeralKeyRotationForTesting(Fast)
            .WithLogger(logger)
            .BuildAsync();
        factory.Armed = true;

        await Task.Delay(Fast * 4);

        var failure = Assert.Single(logger.Entries, e => e.EventId == 7);
        Assert.Equal(LogLevel.Error, failure.Level);
        Assert.Contains("version 1 stays current", failure.Message);
        Assert.True(ring.CurrentVersion >= 2, "a later interval should have rotated");
    }

    [Fact]
    public async Task Dispose_StopsRotation()
    {
        var factory = new RecordingCryptoProviderFactory();
        var ring = await Builder(factory).WithEphemeralKey(1).WithEphemeralKeyRotationForTesting(Fast).BuildAsync();

        await ring.DisposeAsync();
        var callsAtDispose = factory.CreateEphemeralExpirySecondsCalls.Count;
        await Task.Delay(Fast * 3);

        Assert.Equal(callsAtDispose, factory.CreateEphemeralExpirySecondsCalls.Count);
    }

    [Fact]
    public async Task SynchronousDispose_StopsRotationToo()
    {
        var factory = new RecordingCryptoProviderFactory();
        var ring = await Builder(factory).WithEphemeralKey(1).WithEphemeralKeyRotationForTesting(Fast).BuildAsync();

        ring.Dispose();
        var callsAtDispose = factory.CreateEphemeralExpirySecondsCalls.Count;
        await Task.Delay(Fast * 3);

        Assert.Equal(callsAtDispose, factory.CreateEphemeralExpirySecondsCalls.Count);
    }

    [Fact]
    public async Task Dispose_WhileARotationIsWaitingOnTheKeyWrapper_CancelsIt_AndDoesNotThrow()
    {
        var factory = new FlakyFactory { HangUntilCancelled = true };
        var ring = await Builder(factory).WithEphemeralKey(1).WithEphemeralKeyRotationForTesting(Fast).BuildAsync();
        factory.Armed = true;
        await factory.Hanging.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var exception = await Record.ExceptionAsync(async () => await ring.DisposeAsync());

        Assert.Null(exception);
    }

    // --- Retention ---------------------------------------------------------------------------

    [Fact]
    public async Task ARotatingRing_RetiresSupersededEphemeralKeys_OnceTheirRetentionHasPassed()
    {
        var logger = new RecordingLogger<KeyRing>();
        var factory = new RecordingCryptoProviderFactory();
        await using var ring = await Builder(factory)
            .WithEphemeralKey(1)
            .WithEphemeralKeyRotationForTesting(Fast)
            .WithEphemeralKeyRetentionForTesting(Fast * 2.5)
            .WithLogger(logger)
            .BuildAsync();
        var protector = ring.CreateProtector("retention");
        var underV1 = protector.Encrypt("written under v1");
        Assert.Equal(Fast * 2.5, ring.EphemeralKeyRetention);

        await Task.Delay(Fast * 8);

        // Version 1 was superseded long ago and is gone - from the ring and from memory.
        Assert.False(ring.TryGet(1, out _));
        Assert.Throws<KeyNotFoundException>(() => protector.Decrypt(underV1, new char[64]));
        Assert.Contains(logger.Entries, e => e.EventId == 8 && e.Level == LogLevel.Information && e.Message.Contains("version 1 "));
        var first = Assert.IsType<AesGcmCryptoProvider>(factory.CreatedProviders[0]);
        Assert.Throws<ObjectDisposedException>(() => first.Encrypt(new byte[1], new byte[64]));

        // The current key and the one just before it are still within retention.
        var current = ring.CurrentVersion;
        Assert.True(current >= 5, $"CurrentVersion is {current}");
        Assert.True(ring.TryGet(current, out _));
        Assert.True(ring.TryGet(current - 1, out _));
        var result = new char[64];
        var underCurrent = protector.Encrypt("still works");
        Assert.Equal("still works", new string(result, 0, protector.Decrypt(underCurrent, result)));
    }

    [Fact]
    public async Task WithoutRotation_NothingIsEverRetired()
    {
        await using var ring = await Builder(new RecordingCryptoProviderFactory())
            .WithEphemeralKey(1)
            .WithoutEphemeralKeyRotation()
            .WithEphemeralKeyRetentionForTesting(Fast)
            .BuildAsync();

        await Task.Delay(Fast * 3);

        Assert.Null(ring.EphemeralKeyRetention);
        Assert.True(ring.TryGet(1, out _));
    }

    // --- Retention, driven directly with a movable clock ----------------------------------------

    private static long Timestamp(TimeSpan fromNow) => Stopwatch.GetTimestamp() + (long)(fromNow.TotalSeconds * Stopwatch.Frequency);

    [Fact]
    public async Task Retire_KeepsASupersededKey_UntilItsRetentionHasPassed_ThenDisposesAndRemovesIt()
    {
        var logger = new RecordingLogger<KeyRing>();
        using var ring = new KeyRing(new DefaultFormatProvider());
        var superseded = new TrackingKey();
        ring.Add(1, superseded);
        ring.ConfigureEphemeralKeyRetention(TimeSpan.FromHours(1), [1]);

        // The rotation adds 2 and first sees 1 as superseded, starting its retention clock.
        Assert.True(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), logger, CancellationToken.None));
        Assert.True(ring.TryGet(1, out _));

        await ring.RetireSupersededEphemeralKeysAsync(Timestamp(TimeSpan.FromMinutes(59)), logger, CancellationToken.None);
        Assert.True(ring.TryGet(1, out _));
        Assert.False(superseded.Disposed);

        await ring.RetireSupersededEphemeralKeysAsync(Timestamp(TimeSpan.FromMinutes(61)), logger, CancellationToken.None);
        Assert.False(ring.TryGet(1, out _));
        Assert.Throws<KeyNotFoundException>(() => ring.Get(1));
        Assert.True(superseded.Disposed);
        Assert.Equal(2, ring.CurrentVersion);
        Assert.True(ring.TryGet(2, out _));
        var retired = Assert.Single(logger.Entries, e => e.EventId == 8);
        Assert.Contains("version 1 ", retired.Message);
    }

    [Fact]
    public async Task Retire_NeverTouchesKeyFileVersions_OrTheCurrentKey()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        var keyFile = new TrackingKey();
        var ephemeral = new TrackingKey();
        ring.Add(1, keyFile);    // a key file: not ephemeral
        ring.Add(2, ephemeral);
        ring.ConfigureEphemeralKeyRetention(TimeSpan.FromHours(1), [2]);

        Assert.True(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), null, CancellationToken.None));
        await ring.RetireSupersededEphemeralKeysAsync(Timestamp(TimeSpan.FromDays(365)), null, CancellationToken.None);

        Assert.True(ring.TryGet(1, out _));
        Assert.False(keyFile.Disposed);
        Assert.False(ring.TryGet(2, out _));
        Assert.True(ephemeral.Disposed);
        Assert.True(ring.TryGet(3, out _)); // current, however old
        Assert.Equal(3, ring.CurrentVersion);
    }

    [Fact]
    public async Task Retire_WithoutRetentionConfigured_DoesNothing()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new TrackingKey());

        Assert.True(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), null, CancellationToken.None));
        await ring.RetireSupersededEphemeralKeysAsync(Timestamp(TimeSpan.FromDays(365)), null, CancellationToken.None);

        Assert.Null(ring.EphemeralKeyRetention);
        Assert.True(ring.TryGet(1, out _));
    }

    [Fact]
    public async Task Retire_WhenDisposingAKeyThrows_StillRemovesIt_AndLogsAnError()
    {
        var logger = new RecordingLogger<KeyRing>();
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new TrackingKey { ThrowOnDispose = true });
        ring.ConfigureEphemeralKeyRetention(TimeSpan.FromMinutes(1), [1]);
        Assert.True(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), logger, CancellationToken.None));

        await ring.RetireSupersededEphemeralKeysAsync(Timestamp(TimeSpan.FromMinutes(2)), logger, CancellationToken.None);

        Assert.False(ring.TryGet(1, out _));
        var failure = Assert.Single(logger.Entries, e => e.EventId == 9);
        Assert.Equal(LogLevel.Error, failure.Level);
    }

    // --- Single rotations, driven directly -----------------------------------------------------

    [Fact]
    public async Task Rotate_WhenTheNextVersionIsAlreadyTaken_Fails_AndDisposesTheKeyItMade()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new TrackingKey());
        var made = new TrackingKey();

        var rotated = await ring.RotateEphemeralKeyAsync(_ =>
        {
            ring.Add(2, new TrackingKey()); // someone else takes version 2 first
            return ValueTask.FromResult<IDataEncryptionKey>(made);
        }, null, CancellationToken.None);

        Assert.False(rotated);
        Assert.True(made.Disposed);
        Assert.Equal(2, ring.CurrentVersion);
    }

    [Fact]
    public async Task Rotate_AtVersionIntMaxValue_RefusesWithoutCreatingAKey()
    {
        var logger = new RecordingLogger<KeyRing>();
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(int.MaxValue, new TrackingKey());
        var created = false;

        var rotated = await ring.RotateEphemeralKeyAsync(_ =>
        {
            created = true;
            return ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey());
        }, logger, CancellationToken.None);

        Assert.False(rotated);
        Assert.False(created);
        Assert.Equal(int.MaxValue, ring.CurrentVersion);
        Assert.Contains("no higher version", Assert.Single(logger.Entries).Exception!.Message);
    }

    [Fact]
    public async Task Rotate_FailingDuringShutdown_Rethrows_AndStillDisposesTheKeyItMade()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new TrackingKey());
        using var cts = new CancellationTokenSource();
        var made = new TrackingKey();

        await Assert.ThrowsAsync<ArgumentException>(() => ring.RotateEphemeralKeyAsync(_ =>
        {
            cts.Cancel();
            ring.Add(2, new TrackingKey()); // makes the rotation's own Add fail
            return ValueTask.FromResult<IDataEncryptionKey>(made);
        }, null, cts.Token));

        Assert.True(made.Disposed);
    }

    [Fact]
    public async Task Rotate_AtVersionIntMaxValue_WithoutALogger_StillRefuses()
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(int.MaxValue, new TrackingKey());

        Assert.False(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), null, CancellationToken.None));
    }

    [Fact]
    public async Task Rotate_RecordsAnActivityTaggedWithTheNewVersion()
    {
        var rotations = new List<System.Diagnostics.Activity>();
        using var listener = new System.Diagnostics.ActivityListener
        {
            ShouldListenTo = source => source.Name == "HkdfGuard.DataEncryptionKey",
            Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _) =>
                System.Diagnostics.ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName == HkdfGuard.Diagnostics.ActivityNames.DataProtection.KeyRingRotateEphemeral)
                    lock (rotations)
                        rotations.Add(activity);
            },
        };
        System.Diagnostics.ActivitySource.AddActivityListener(listener);
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(41, new TrackingKey());

        Assert.True(await ring.RotateEphemeralKeyAsync(_ => ValueTask.FromResult<IDataEncryptionKey>(new TrackingKey()), null, CancellationToken.None));

        System.Diagnostics.Activity rotation;
        lock (rotations)
            rotation = Assert.Single(rotations);
        Assert.Equal(42, rotation.GetTagItem(HkdfGuard.Diagnostics.AttributeNames.KeyVersion));
    }

    // --- Helpers -------------------------------------------------------------------------------

    private sealed class TrackingKey : IDataEncryptionKey, IAsyncDisposable
    {
        public bool Disposed { get; private set; }
        public bool ThrowOnDispose { get; init; }

        public byte[] Encrypt(Span<byte> plaintext) => [];
        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad) => [];
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => 0;
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => 0;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ThrowOnDispose ? ValueTask.FromException(new InvalidOperationException("dispose failed")) : ValueTask.CompletedTask;
        }
    }

    // Creates real providers, but once armed can fail a set number of times or hang until cancelled.
    private sealed class FlakyFactory : ICryptoProviderFactory
    {
        private readonly AesGcmCryptoProviderFactory _inner = new();
        private int _failures;

        public volatile bool Armed;
        public int FailuresBeforeSuccess { get; init; }
        public bool HangUntilCancelled { get; init; }
        public TaskCompletionSource Hanging { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<ICryptoProvider> CreateAsync(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds,
            int? maxRefreshFailures = null, CancellationToken cancellationToken = default)
            => _inner.CreateAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures, cancellationToken);

        public async ValueTask<ICryptoProvider> CreateEphemeralAsync(IKeyWrapper wrapper, int expirySeconds,
            int? maxRefreshFailures = null, CancellationToken cancellationToken = default)
        {
            if (Armed && HangUntilCancelled)
            {
                Hanging.TrySetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            if (Armed && Interlocked.Increment(ref _failures) <= FailuresBeforeSuccess)
                throw new CryptographicException("KEK unavailable");

            return await _inner.CreateEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures, cancellationToken);
        }
    }
}
