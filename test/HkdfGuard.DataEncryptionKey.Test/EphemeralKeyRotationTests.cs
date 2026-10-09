using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// Scheduled ephemeral key rotation: a ring with ephemeral keys adds a fresh one at
/// CurrentVersion + 1 every interval, keeps every earlier key for decryption, and stops rotating
/// when disposed.
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
    [InlineData(1)]       // the minimum, one minute
    [InlineData(60)]
    [InlineData(6 * 60)]
    public void WithEphemeralKeyRotation_AcceptsTheRange(int minutes)
    {
        var builder = new KeyRingBuilder();

        Assert.Same(builder, builder.WithEphemeralKeyRotation(TimeSpan.FromMinutes(minutes)));
        Assert.Equal(TimeSpan.FromMinutes(minutes), builder.EphemeralKeyRotationInterval);
    }

    [Fact]
    public void WithEphemeralKeyRotation_AcceptsTheMaximum_AndRefusesBeyondEitherEnd()
    {
        new KeyRingBuilder().WithEphemeralKeyRotation(KeyRingBuilder.MaxEphemeralKeyRotationInterval);

        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRotation(TimeSpan.FromSeconds(59)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithEphemeralKeyRotation(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new KeyRingBuilder().WithEphemeralKeyRotation(KeyRingBuilder.MaxEphemeralKeyRotationInterval + TimeSpan.FromMilliseconds(1)));
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

        public byte[] Encrypt(Span<byte> plaintext) => [];
        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad) => [];
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => 0;
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => 0;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
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
