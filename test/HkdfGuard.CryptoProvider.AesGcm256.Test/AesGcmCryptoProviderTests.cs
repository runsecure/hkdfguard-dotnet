using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

public class AesGcmCryptoProviderTests
{
    [Fact]
    public async Task CreateAsync_BuildsInitialSessionEagerly()
    {
        var wrapper = new FakeKeyWrapper();

        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public async Task CreateAsync_WhenKeyWrapperFails_Throws()
    {
        var wrapper = new FakeKeyWrapper { ThrowOnDecrypt = new InvalidOperationException("reveal failed") };

        await Assert.ThrowsAsync<InvalidOperationException>(() => AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    public async Task CreateAsync_WithExpirySecondsOutOfRange_ThrowsArgumentOutOfRangeException(int expirySeconds)
    {
        var wrapper = new FakeKeyWrapper();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), expirySeconds));
    }

    [Fact]
    public async Task BackgroundTimer_ProactivelyRefreshesTheSessionWithoutAnyGetSessionCall()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);

        // No GetSession call at all - only the constructor's eager build (DecryptCallCount == 1)
        // and the background timer, ticking every expirySeconds, should have run by now.
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.Equal(2, wrapper.DecryptCallCount);
    }

    [Fact]
    public async Task Dispose_DisposesTheCurrentSessionAndStopsTheBackgroundTimer()
    {
        var wrapper = new FakeKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);

        provider.Dispose();
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        // Only the constructor's eager build - the timer must not have fired after Dispose.
        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public async Task GetEncryptedAllocationLength_AddsNonceAndTagOverhead()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(10 + 12 + 16, provider.GetEncryptedAllocationLength(10));
    }

    [Fact]
    public async Task GetDecryptedAllocationLength_RemovesNonceAndTagOverhead()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(10, provider.GetDecryptedAllocationLength(10 + 12 + 16));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(27)]
    [InlineData(28)]
    public async Task GetDecryptedAllocationLength_ForInputNoLongerThanTheOverhead_IsZero(int length)
    {
        using var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);

        Assert.Equal(0, provider.GetDecryptedAllocationLength(length));
    }

    [Fact]
    public async Task Dispose_CalledTwice_DoesNotThrow()
    {
        var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);

        provider.Dispose();
        provider.Dispose();
    }

    [Fact]
    public async Task DisposeAsync_DisposesTheCurrentSessionAndStopsTheBackgroundTimer()
    {
        var wrapper = new FakeKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);

        await provider.DisposeAsync();
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        // Only the eager first reveal - the timer must not have fired after DisposeAsync.
        Assert.Equal(1, wrapper.DecryptCallCount);
        Assert.Throws<ObjectDisposedException>(() => provider.Encrypt(new byte[] { 1 }, new byte[64]));
    }

    [Fact]
    public async Task DisposeAsync_CalledTwiceOrMixedWithDispose_DoesNotThrow()
    {
        var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);

        await provider.DisposeAsync();
        await provider.DisposeAsync();
        provider.Dispose();
    }

    [Fact]
    public async Task DisposeAsync_WhileARefreshIsFailingBecauseOfTheShutdown_DoesNotThrow()
    {
        var wrapper = new FailsOnShutdownKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        await wrapper.RefreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var exception = await Record.ExceptionAsync(async () => await provider.DisposeAsync());

        Assert.Null(exception);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public async Task CreateAsync_WhenTheKeyWrapperRevealsAWrongLengthKey_ThrowsRatherThanUseAPartialKey(int bytesWritten)
    {
        var wrapper = new FakeKeyWrapper { UnwrapBytesWrittenOverride = bytesWritten };

        var exception = await Assert.ThrowsAsync<CryptographicException>(() => AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));

        Assert.Contains($"revealed {bytesWritten} bytes", exception.Message);
    }

    [Fact]
    public async Task BackgroundRefresh_WhenTheKeyWrapperRevealsAWrongLengthKey_RecordsItAndKeepsTheCurrentSession()
    {
        var failures = new List<Activity>();
        using var listener = ListenTo(ActivityNames.CryptoProviderAesGcm256.BackgroundRefresh, failures);
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        var plaintext = "still works"u8.ToArray();
        var ciphertext = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt((byte[])plaintext.Clone(), ciphertext);

        wrapper.UnwrapBytesWrittenOverride = 16;
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.True(wrapper.DecryptCallCount >= 2);
        Assert.Contains(failures, a => a.Status == ActivityStatusCode.Error && a.StatusDescription!.Contains("revealed 16 bytes"));
        var decrypted = new byte[plaintext.Length];
        provider.Decrypt(ciphertext.AsSpan(0, written), decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task BackgroundRefresh_WhenTheKeyWrapperFails_RecordsItAndKeepsTheCurrentSession()
    {
        var failures = new List<Activity>();
        using var listener = ListenTo(ActivityNames.CryptoProviderAesGcm256.BackgroundRefresh, failures);
        var wrapper = new FakeKeyWrapper();
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        var plaintext = "still works"u8.ToArray();
        var ciphertext = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt((byte[])plaintext.Clone(), ciphertext);

        wrapper.ThrowOnDecrypt = new CryptographicException("unwrap failed");
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        Assert.True(wrapper.DecryptCallCount >= 2);
        Assert.Contains(failures, a => a.Status == ActivityStatusCode.Error);
        var decrypted = new byte[plaintext.Length];
        provider.Decrypt(ciphertext.AsSpan(0, written), decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task Dispose_WhileARefreshIsFailingBecauseOfTheShutdown_DoesNotThrow()
    {
        // Regression test: a key wrapper that reacts to Dispose's cancellation by failing with a
        // non-cancellation exception (e.g. a network client torn down mid-call) used to fault the
        // refresh task, and Dispose then rethrew it.
        var wrapper = new FailsOnShutdownKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        await wrapper.RefreshStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var exception = Record.Exception(provider.Dispose);

        Assert.Null(exception);
    }

    private static ActivityListener ListenTo(string activityName, List<Activity> stopped)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "HkdfGuard.CryptoProvider.AesGcm256",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName == activityName)
                    lock (stopped) stopped.Add(activity);
            },
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    // Reveals a key once (the constructor's eager build); every later unwrap waits until cancelled,
    // then fails with a CryptographicException rather than an OperationCanceledException.
    private sealed class FailsOnShutdownKeyWrapper : IKeyWrapper
    {
        private int _calls;

        public TaskCompletionSource RefreshStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                RandomNumberGenerator.Fill(result.Span[..32]);
                return 32;
            }

            RefreshStarted.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw new CryptographicException("KMS connection closed during shutdown.");
            }

            return 0;
        }
    }

    [Fact]
    public async Task BackgroundRefresh_UnderConcurrentLoad_NeverFailsAnOperationMidSwap()
    {
        // A stable key, as a real wrapper gives for one wrapped payload: ciphertext produced just
        // before a swap must decrypt just after it.
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        var deadline = DateTime.UtcNow.AddSeconds(2.5);
        var failures = new List<Exception>();

        var workers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            var plaintext = "pounding on it"u8.ToArray();
            var ciphertext = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
            var decrypted = new byte[plaintext.Length];
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    var written = provider.Encrypt((byte[])plaintext.Clone(), ciphertext);
                    provider.Decrypt(ciphertext.AsSpan(0, written), decrypted);
                }
                catch (Exception ex)
                {
                    lock (failures) failures.Add(ex);
                    return;
                }
            }
        })).ToArray();
        await Task.WhenAll(workers);

        Assert.Empty(failures);
    }

    [Fact]
    public async Task Dispose_AfterRefreshes_DisposesTheRetiredSessionAsWellAsTheCurrentOne()
    {
        var wrapper = new FakeKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);

        // Two ticks: the first retires the constructor's session, the second disposes it and
        // retires the first refresh's session - leaving one current and one retiring at Dispose.
        await Task.Delay(TimeSpan.FromSeconds(2.5));
        Assert.True(wrapper.DecryptCallCount >= 3);

        var exception = Record.Exception(provider.Dispose);

        Assert.Null(exception);
        Assert.Throws<ObjectDisposedException>(() => provider.Encrypt(new byte[] { 1 }, new byte[64]));
    }

    [Fact]
    public async Task Encrypt_PastTheKeysLimit_ThrowsWhileDecryptStillWorks()
    {
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60, new EncryptionBudget(warningThreshold: 1, limit: 2));
        var plaintext = "value"u8.ToArray();
        var ciphertext = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];

        var written = provider.Encrypt((byte[])plaintext.Clone(), ciphertext);
        provider.Encrypt((byte[])plaintext.Clone(), new byte[ciphertext.Length]);

        var exception = Assert.Throws<CryptographicException>(() => provider.Encrypt((byte[])plaintext.Clone(), new byte[ciphertext.Length]));
        Assert.Contains("must be rotated", exception.Message);
        Assert.Equal(2, provider.EncryptionCount);

        var decrypted = new byte[plaintext.Length];
        provider.Decrypt(ciphertext.AsSpan(0, written), decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task EncryptionCount_SurvivesABackgroundRefresh_BecauseTheKeyIsTheSame()
    {
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, new EncryptionBudget(warningThreshold: 1, limit: 4));
        provider.Encrypt("one"u8.ToArray(), new byte[64]);
        provider.Encrypt("two"u8.ToArray(), new byte[64]);

        await Task.Delay(TimeSpan.FromSeconds(1.5));
        Assert.True(wrapper.DecryptCallCount >= 2);
        provider.Encrypt("three"u8.ToArray(), new byte[64]);
        provider.Encrypt("four"u8.ToArray(), new byte[64]);

        Assert.Equal(4, provider.EncryptionCount);
        Assert.Throws<CryptographicException>(() => provider.Encrypt("five"u8.ToArray(), new byte[64]));
    }

    [Fact]
    public async Task Encrypt_CrossingTheWarningThreshold_RaisesTheBudgetWarningEventOnce()
    {
        var encrypts = new List<Activity>();
        using var listener = ListenTo(ActivityNames.CryptoProviderAesGcm256.Encrypt, encrypts);
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        // The listener sees every AES-GCM encrypt span in the process, including those of tests
        // running in parallel, so this test's warning is identified by a limit no other test uses.
        const long limit = 7919;
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60, new EncryptionBudget(warningThreshold: 2, limit: limit));

        for (var i = 0; i < 4; i++)
            provider.Encrypt("value"u8.ToArray(), new byte[64]);

        List<ActivityEvent> warnings;
        lock (encrypts)
            warnings = encrypts.SelectMany(a => a.Events)
                .Where(e => e.Name == EventNames.EncryptionBudgetWarning
                            && e.Tags.Any(t => t.Key == AttributeNames.EncryptionLimit && Equals(t.Value, limit)))
                .ToList();
        var warning = Assert.Single(warnings);
        Assert.Equal(2L, warning.Tags.Single(t => t.Key == AttributeNames.EncryptionCount).Value);
    }

    [Fact]
    public void PublicLimits_MatchTheBudgetDefaults()
    {
        Assert.Equal(1L << 31, AesGcmCryptoProvider.MaxEncryptionsPerKey);
        Assert.Equal(1L << 28, AesGcmCryptoProvider.EncryptionWarningThreshold);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task CreateAsync_WithMaxRefreshFailuresBelowOne_Throws(int maxRefreshFailures)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60, maxRefreshFailures));
    }

    [Fact]
    public async Task FailClosed_IsTheDefault_AndNullOptsIntoFailOpen()
    {
        using var defaulted = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);
        using var failOpen = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60, maxRefreshFailures: null);

        Assert.Equal(RefreshFailurePolicy.DefaultMaxRefreshFailures, defaulted.MaxRefreshFailures);
        Assert.Equal(3, RefreshFailurePolicy.DefaultMaxRefreshFailures);
        Assert.Null(failOpen.MaxRefreshFailures);
        Assert.False(defaulted.KeyAccessSuspended);
    }

    // --- One encryption budget per key, process-wide -------------------------------------------

    [Fact]
    public async Task TwoProvidersRevealingTheSameKey_DrawOnOneEncryptionCount()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var first = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper { FixedKey = key }, "wrapped"u8.ToArray(), 60);
        using var second = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper { FixedKey = key }, "wrapped"u8.ToArray(), 60);
        using var other = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) }, "wrapped"u8.ToArray(), 60);

        first.Encrypt("one"u8.ToArray(), new byte[64]);
        second.Encrypt("two"u8.ToArray(), new byte[64]);
        second.Encrypt("three"u8.ToArray(), new byte[64]);

        Assert.Equal(3, first.EncryptionCount);
        Assert.Equal(3, second.EncryptionCount);
        Assert.Equal(0, other.EncryptionCount);
    }

    [Fact]
    public async Task TheSharedCount_OutlivesAProvider_SoRebuildingFromTheSameKeyFileDoesNotResetIt()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var first = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper { FixedKey = key }, "wrapped"u8.ToArray(), 60);
        first.Encrypt("one"u8.ToArray(), new byte[64]);
        await first.DisposeAsync();

        using var rebuilt = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper { FixedKey = key }, "wrapped"u8.ToArray(), 60);

        Assert.Equal(1, rebuilt.EncryptionCount);
    }

    [Fact]
    public void TheRegistry_IsKeyedByAnHmac_NotTheKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);

        Assert.Same(EncryptionBudget.For(key), EncryptionBudget.For((byte[])key.Clone()));
        Assert.NotSame(EncryptionBudget.For(key), EncryptionBudget.For(RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public async Task CrossingTheWarningThreshold_IsAlsoLogged_SoItIsSeenWithoutAnActivityListener()
    {
        var logger = new RecordingLogger<AesGcmCryptoProvider>();
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60, null,
            new EncryptionBudget(warningThreshold: 2, limit: 10), CancellationToken.None, logger);

        for (var i = 0; i < 4; i++)
            provider.Encrypt("value"u8.ToArray(), new byte[64]);

        var warning = Assert.Single(logger.Entries, e => e.EventId == 10);
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Contains("2 encryptions of its 10", warning.Message);
    }

    [Fact]
    public async Task FailClosed_AfterTheConfiguredConsecutiveFailures_SuspendsOperationsUntilARefreshSucceeds()
    {
        var refreshes = new List<Activity>();
        using var listener = ListenTo(ActivityNames.CryptoProviderAesGcm256.BackgroundRefresh, refreshes);
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: 2);
        var plaintext = "survives"u8.ToArray();
        var ciphertext = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt((byte[])plaintext.Clone(), ciphertext);

        // Two consecutive failed refreshes (ticks at ~1 s and ~2 s).
        wrapper.ThrowOnDecrypt = new CryptographicException("KEK unavailable");
        await Task.Delay(TimeSpan.FromSeconds(2.6));

        Assert.True(provider.KeyAccessSuspended);
        var encryptError = Assert.Throws<CryptographicException>(() => provider.Encrypt("x"u8.ToArray(), new byte[64]));
        Assert.Contains("suspended", encryptError.Message);
        Assert.Throws<CryptographicException>(() => provider.Decrypt(ciphertext.AsSpan(0, written), new byte[plaintext.Length]));
        var suspended = Assert.Single(refreshes.SelectMany(a => a.Events), e => e.Name == EventNames.KeyAccessSuspended);
        Assert.Equal(2, suspended.Tags.Single(t => t.Key == AttributeNames.ConsecutiveFailures).Value);

        // The KEK comes back: the next successful refresh resumes service with the same DEK.
        wrapper.ThrowOnDecrypt = null;
        await Task.Delay(TimeSpan.FromSeconds(1.3));

        Assert.False(provider.KeyAccessSuspended);
        var decrypted = new byte[plaintext.Length];
        provider.Decrypt(ciphertext.AsSpan(0, written), decrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task FailClosed_LogsEveryFailedRefresh_TheSuspension_AndTheResumption()
    {
        var logger = new RecordingLogger<AesGcmCryptoProvider>();
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1,
            maxRefreshFailures: 2, logger: logger);
        var revoked = new CryptographicException("KEK revoked");

        wrapper.ThrowOnDecrypt = revoked;                                // ticks ~1 s and ~2 s fail
        await Task.Delay(TimeSpan.FromSeconds(2.6));

        var failures = logger.Entries.Where(e => e.EventId == 3).ToList();
        Assert.Equal(2, failures.Count);
        Assert.All(failures, e =>
        {
            Assert.Equal(LogLevel.Error, e.Level);
            Assert.Same(revoked, e.Exception);
            Assert.Contains("fail closed after 2 consecutive failures", e.Message);
        });
        var suspended = Assert.Single(logger.Entries, e => e.EventId == 4);
        Assert.Equal(LogLevel.Critical, suspended.Level);
        Assert.Contains("after 2 consecutive failed refreshes", suspended.Message);
        Assert.DoesNotContain(logger.Entries, e => e.EventId == 5);

        wrapper.ThrowOnDecrypt = null;                                   // tick ~3 s succeeds
        await Task.Delay(TimeSpan.FromSeconds(1.0));

        var resumed = Assert.Single(logger.Entries, e => e.EventId == 5);
        Assert.Equal(LogLevel.Information, resumed.Level);
        Assert.False(provider.KeyAccessSuspended);
    }

    [Fact]
    public async Task FailOpen_StillLogsEveryFailedRefreshAsAnError_ButNeverSuspends()
    {
        var logger = new RecordingLogger<AesGcmCryptoProvider>();
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: null, logger: logger);

        wrapper.ThrowOnDecrypt = new CryptographicException("KEK unreachable");
        await Task.Delay(TimeSpan.FromSeconds(2.6));

        var failures = logger.Entries.Where(e => e.EventId == 3).ToList();
        Assert.True(failures.Count >= 2);
        Assert.All(failures, e => Assert.Contains("fail open", e.Message));
        Assert.Contains(failures, e => e.Message.Contains("(2 consecutive)"));
        Assert.DoesNotContain(logger.Entries, e => e.EventId is 4 or 5);
        Assert.False(provider.KeyAccessSuspended);

        // A success after failures under fail-open resets the count but was never a suspension.
        wrapper.ThrowOnDecrypt = null;
        await Task.Delay(TimeSpan.FromSeconds(1.2));
        Assert.DoesNotContain(logger.Entries, e => e.EventId == 5);
    }

    [Fact]
    public async Task SuccessfulRefreshes_LogNothing()
    {
        var logger = new RecordingLogger<AesGcmCryptoProvider>();
        using var provider = await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 1,
            maxRefreshFailures: 1, logger: logger);

        await Task.Delay(TimeSpan.FromSeconds(1.3));

        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task FailClosed_CountsOnlyConsecutiveFailures_ASuccessResetsTheCount()
    {
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: 2);

        wrapper.ThrowOnDecrypt = new CryptographicException("blip");   // tick ~1 s fails
        await Task.Delay(TimeSpan.FromSeconds(1.3));
        wrapper.ThrowOnDecrypt = null;                                   // tick ~2 s succeeds
        await Task.Delay(TimeSpan.FromSeconds(1.0));
        wrapper.ThrowOnDecrypt = new CryptographicException("blip");   // tick ~3 s fails
        await Task.Delay(TimeSpan.FromSeconds(1.0));

        Assert.True(wrapper.DecryptCallCount >= 4);
        Assert.False(provider.KeyAccessSuspended);
        Assert.Equal("still open".Length + 28, provider.Encrypt("still open"u8.ToArray(), new byte[64]));
    }

    [Fact]
    public async Task Dispose_WhileSuspended_DoesNotThrow_AndLaterUseReportsDisposedNotSuspended()
    {
        var wrapper = new FakeKeyWrapper();
        var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: 1);
        wrapper.ThrowOnDecrypt = new CryptographicException("KEK unavailable");
        await Task.Delay(TimeSpan.FromSeconds(1.5));
        Assert.True(provider.KeyAccessSuspended);

        var exception = Record.Exception(provider.Dispose);

        Assert.Null(exception);
        Assert.False(provider.KeyAccessSuspended);
        Assert.Throws<ObjectDisposedException>(() => provider.Encrypt(new byte[] { 1 }, new byte[64]));
    }

    [Fact]
    public async Task FailClosed_AfterASuccessfulRefresh_DisposesTheRetiredSessionToo()
    {
        var wrapper = new FakeKeyWrapper { FixedKey = RandomNumberGenerator.GetBytes(32) };
        using var provider = await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1, maxRefreshFailures: 1);

        await Task.Delay(TimeSpan.FromSeconds(1.3));                        // tick ~1 s succeeds: a session is retired
        Assert.True(wrapper.DecryptCallCount >= 2);
        wrapper.ThrowOnDecrypt = new CryptographicException("KEK revoked");
        await Task.Delay(TimeSpan.FromSeconds(1.0));                        // tick ~2 s fails: suspend

        Assert.True(provider.KeyAccessSuspended);
        Assert.Throws<CryptographicException>(() => provider.Encrypt("x"u8.ToArray(), new byte[64]));
    }
}
