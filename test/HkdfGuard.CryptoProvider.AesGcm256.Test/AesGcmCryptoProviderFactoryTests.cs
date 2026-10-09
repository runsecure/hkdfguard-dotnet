using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

public class AesGcmCryptoProviderFactoryTests
{
    private static readonly AesGcmCryptoProviderFactory Factory = new();

    private static void AssertRoundTrips(ICryptoProvider provider)
    {
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt(plaintext, encrypted);

        var decrypted = new byte[expected.Length];
        Assert.Equal(expected.Length, provider.Decrypt(encrypted.AsSpan(0, written), decrypted));
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public async Task CreateAsync_ProducesAWorkingProvider()
    {
        using var provider = await Factory.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);

        AssertRoundTrips(provider);
    }

    [Fact]
    public async Task CreateEphemeralAsync_CallsGenerateAndWrapExactlyOnce()
    {
        var wrapper = new FakeKeyWrapper();

        using var provider = await Factory.CreateEphemeralAsync(wrapper, 60);

        Assert.Equal(1, wrapper.GenerateAndWrapCallCount);
        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public async Task CreateEphemeralAsync_ProducesAWorkingProvider()
    {
        using var provider = await Factory.CreateEphemeralAsync(new FakeKeyWrapper(), 60);

        AssertRoundTrips(provider);
    }

    [Fact]
    public async Task CreateAndCreateEphemeral_PassTheRefreshFailurePolicyThrough()
    {
        using var created = await Factory.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60, maxRefreshFailures: 4);
        using var ephemeral = await Factory.CreateEphemeralAsync(new FakeKeyWrapper(), 60, maxRefreshFailures: 5);
        using var defaulted = await Factory.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60);

        Assert.Equal(4, Assert.IsType<AesGcmCryptoProvider>(created).MaxRefreshFailures);
        Assert.Equal(5, Assert.IsType<AesGcmCryptoProvider>(ephemeral).MaxRefreshFailures);
        Assert.Null(Assert.IsType<AesGcmCryptoProvider>(defaulted).MaxRefreshFailures);
    }

    [Fact]
    public async Task CreateAndCreateEphemeral_HandTheFactorysLoggerToEveryProvider()
    {
        var logger = new RecordingLogger<AesGcmCryptoProvider>();
        var factory = new AesGcmCryptoProviderFactory(logger);
        var wrapper = new FakeKeyWrapper();

        using var created = await factory.CreateAsync(wrapper, "wrapped"u8.ToArray(), 1);
        using var ephemeral = await factory.CreateEphemeralAsync(wrapper, 1);
        wrapper.ThrowOnDecrypt = new CryptographicException("KEK revoked");
        await Task.Delay(TimeSpan.FromSeconds(1.4));

        // One failed refresh from each provider.
        Assert.True(logger.Entries.Count(e => e.EventId == 3) >= 2);
    }

    [Fact]
    public async Task CreateAsync_AwaitsASlowKeyWrapperInsteadOfBlockingTheCaller()
    {
        var wrapper = new GatedKeyWrapper();

        var pending = Factory.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60).AsTask();

        // The reveal is still waiting on the "network": the call has already returned to us.
        await wrapper.UnwrapStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(pending.IsCompleted);

        wrapper.Release();
        using var provider = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        AssertRoundTrips(provider);
    }

    [Fact]
    public async Task CreateEphemeralAsync_AwaitsASlowKeyWrapperInsteadOfBlockingTheCaller()
    {
        var wrapper = new GatedKeyWrapper();

        var pending = Factory.CreateEphemeralAsync(wrapper, 60).AsTask();

        await wrapper.UnwrapStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(pending.IsCompleted);

        wrapper.Release();
        using var provider = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        AssertRoundTrips(provider);
    }

    [Fact]
    public async Task CreateAndCreateEphemeral_WhenAlreadyCancelled_NeverCallTheKeyWrapper()
    {
        // FakeKeyWrapper ignores cancellation, so this proves the factory checks the token itself.
        var wrapper = new FakeKeyWrapper();
        var cancelled = new CancellationToken(true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Factory.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60, cancellationToken: cancelled));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await Factory.CreateEphemeralAsync(wrapper, 60, cancellationToken: cancelled));

        Assert.Equal(0, wrapper.DecryptCallCount);
        Assert.Equal(0, wrapper.GenerateAndWrapCallCount);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(301, null)]
    [InlineData(60, 0)]
    public async Task CreateAndCreateEphemeral_WithBadArguments_FailBeforeCallingTheKeyWrapper(int expirySeconds, int? maxRefreshFailures)
    {
        var wrapper = new FakeKeyWrapper();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await Factory.CreateAsync(wrapper, "wrapped"u8.ToArray(), expirySeconds, maxRefreshFailures));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await Factory.CreateEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures));

        Assert.Equal(0, wrapper.DecryptCallCount);
        Assert.Equal(0, wrapper.GenerateAndWrapCallCount);
    }

    [Fact]
    public async Task CreateAsync_WhenTheFirstRevealFails_Throws()
    {
        var wrapper = new FakeKeyWrapper { ThrowOnDecrypt = new CryptographicException("KEK unavailable") };

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Factory.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
    }

    [Fact]
    public async Task ProviderCreateAsync_RejectsAWrongLengthKey_LikeTheConstructor()
    {
        var wrapper = new FakeKeyWrapper { UnwrapBytesWrittenOverride = 16 };

        var exception = await Assert.ThrowsAsync<CryptographicException>(() =>
            AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        Assert.Contains("revealed 16 bytes", exception.Message);
    }

    // A key wrapper whose unwrap waits until released - standing in for a network-backed KMS -
    // so a test can observe the creating call returning before the key is revealed.
    private sealed class GatedKeyWrapper : IKeyWrapper
    {
        private readonly TaskCompletionSource _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

        public TaskCompletionSource UnwrapStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Release() => _gate.TrySetResult();

        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
        {
            "wrapped"u8.CopyTo(result.Span);
            return ValueTask.FromResult(7);
        }

        public async ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
        {
            UnwrapStarted.TrySetResult();
            await _gate.Task.WaitAsync(cancellationToken);
            _key.CopyTo(result);
            return _key.Length;
        }
    }
}
