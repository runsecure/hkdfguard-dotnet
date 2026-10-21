using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class KeyRingBuilderTests
{
    private static readonly ICryptoProviderFactory CryptoProviderFactory = new AesGcmCryptoProviderFactory();

    [Fact]
    public void WithServiceName_SetsServiceName()
    {
        var builder = new KeyRingBuilder().WithServiceName("my.service");

        Assert.Equal("my.service", builder.ServiceName);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(300)]
    public void WithKeyRefreshInterval_WithinRange_SetsKeyRefreshInterval(int keyRefreshInterval)
    {
        var builder = new KeyRingBuilder().WithKeyRefreshInterval(keyRefreshInterval);

        Assert.Equal(keyRefreshInterval, builder.KeyRefreshInterval);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(301)]
    public void WithKeyRefreshInterval_OutOfRange_Throws(int keyRefreshInterval)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithKeyRefreshInterval(keyRefreshInterval));
    }

    [Fact]
    public async Task Build_WithoutKeyWrapper_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync());
        Assert.Equal("A key wrapper is required - call WithKeyWrapper first.", exception.Message);
    }

    [Fact]
    public async Task Build_WithoutCryptoProviderFactory_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync());
        Assert.Equal("A crypto provider factory is required - call WithCryptoProviderFactory first.", exception.Message);
    }

    [Fact]
    public async Task Build_WithoutKeyFilesOrEphemeralKeys_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60);

        await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync());
    }

    [Fact]
    public async Task Build_WithoutKeyRefreshInterval_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithEphemeralKey(1);

        await Assert.ThrowsAsync<InvalidOperationException>(() => builder.BuildAsync());
    }

    [Fact]
    public async Task Build_WithKeyFile_RegistersVersionFromFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());

            var ring = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(CryptoProviderFactory)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path)
                .BuildAsync();

            Assert.Equal(1, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Build_WithMultipleKeyFiles_HighestVersionBecomesCurrent()
    {
        var path1 = Path.GetTempFileName();
        var path2 = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path1, "wrapped-v1"u8.ToArray());
            File.WriteAllBytes(path2, "wrapped-v2"u8.ToArray());

            var ring = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(CryptoProviderFactory)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path1)
                .WithKeyFile(2, path2)
                .BuildAsync();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path1);
            File.Delete(path2);
        }
    }

    [Fact]
    public async Task Build_WithEphemeralKey_RegistersVersion()
    {
        var ring = await new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1)
            .BuildAsync();

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public async Task Build_WithEphemeralKey_ProducesAWorkingKey()
    {
        var ring = await new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1)
            .BuildAsync();

        var key = ring.Get(1);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public async Task Build_WithKeyFileAndHigherVersionEphemeralKey_EphemeralBecomesCurrent()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());

            var ring = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(CryptoProviderFactory)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .BuildAsync();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Build_UsesConfiguredFormatProvider()
    {
        var recordingFormatProvider = new RecordingFormatProvider();

        var ring = await new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1)
            .WithFormatProvider(recordingFormatProvider)
            .BuildAsync();

        ring.CreateProtector("purpose").Encrypt("hello".AsSpan());

        Assert.True(recordingFormatProvider.FormatCalled);
    }

    [Fact]
    public async Task Build_WithKeyFile_PassesKeyRefreshIntervalToTheCryptoProviderFactory()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var recordingFactory = new RecordingCryptoProviderFactory();

            _ = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(recordingFactory)
                .WithKeyRefreshInterval(123)
                .WithKeyFile(1, path)
                .BuildAsync();

            Assert.Equal([123], recordingFactory.CreateExpirySecondsCalls);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Build_WithEphemeralKey_PassesKeyRefreshIntervalRatherThanVersionToTheCryptoProviderFactory()
    {
        // Regression test: CreateEphemeral used to be called with the KeyRing version instead of
        // KeyRefreshInterval - a version of 1 would silently become a 1-second session lifetime.
        var recordingFactory = new RecordingCryptoProviderFactory();

        _ = await new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(recordingFactory)
            .WithKeyRefreshInterval(123)
            .WithEphemeralKey(42)
            .BuildAsync();

        Assert.Equal([123], recordingFactory.CreateEphemeralExpirySecondsCalls);
    }

    [Fact]
    public async Task Build_WhenAVersionIsRegisteredTwice_DisposesEveryProviderItCreated()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var factory = new RecordingCryptoProviderFactory();
            var builder = new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(factory)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path)
                .WithEphemeralKey(1);

            await Assert.ThrowsAsync<ArgumentException>(() => builder.BuildAsync());

            Assert.Equal(2, factory.CreatedProviders.Count);
            Assert.All(factory.CreatedProviders, AssertDisposed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Build_WhenAKeyFileCannotBeRead_DisposesTheProvidersAlreadyCreated()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var factory = new RecordingCryptoProviderFactory();
            var builder = new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(factory)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path)
                .WithKeyFile(2, Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.bin"));

            await Assert.ThrowsAsync<FileNotFoundException>(() => builder.BuildAsync());

            var created = Assert.Single(factory.CreatedProviders);
            AssertDisposed(created);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>A key wrapper that reads its own key files - as the native one does - recording each path.</summary>
    private sealed class ReadingKeyWrapper(byte[] key, byte[] fileContents) : IKeyWrapper
    {
        private readonly FakeKeyWrapper _inner = new(key);

        public List<string> PathsRead { get; } = [];

        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => _inner.WrapAsync(plaintext, result, cancellationToken);

        public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
            => _inner.UnwrapAsync(wrapped, result, cancellationToken);

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
            => _inner.GenerateAndWrapAsync(result, cancellationToken);

        public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        {
            PathsRead.Add(path);
            return ValueTask.FromResult(fileContents);
        }
    }

    [Fact]
    public async Task Build_ReadsEveryKeyFileThroughItsKeyWrapper_NotItself()
    {
        // Neither path exists: only the key wrapper is asked to read them.
        var wrapper = new ReadingKeyWrapper(RandomNumberGenerator.GetBytes(32), "wrapped"u8.ToArray());
        var first = Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.bin");
        var second = Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.bin");

        await using var ring = await new KeyRingBuilder()
            .WithKeyWrapper(wrapper)
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithKeyFile(2, second)
            .WithKeyFile(1, first)
            .BuildAsync();

        Assert.Equal([first, second], wrapper.PathsRead);
        Assert.Equal(2, ring.CurrentVersion);
    }

    [Fact]
    public async Task Build_WithAKeyFileAboveEveryEphemeralVersionAndRotationOn_ThrowsBeforeReadingAnyKeyFile()
    {
        var wrapper = new ReadingKeyWrapper(RandomNumberGenerator.GetBytes(32), "wrapped"u8.ToArray());
        var factory = new RecordingCryptoProviderFactory();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => new KeyRingBuilder()
            .WithKeyWrapper(wrapper)
            .WithCryptoProviderFactory(factory)
            .WithKeyRefreshInterval(60)
            .WithKeyFile(10, "dek.bin")
            .WithEphemeralKey(1)
            .BuildAsync());

        Assert.StartsWith("Key file version 10 is above every ephemeral version", exception.Message);
        Assert.Empty(wrapper.PathsRead);
        Assert.Empty(factory.CreatedProviders);
    }

    [Fact]
    public async Task Build_WithAKeyFileAboveEveryEphemeralVersionAndRotationOff_KeepsTheKeyFileCurrent()
    {
        var wrapper = new ReadingKeyWrapper(RandomNumberGenerator.GetBytes(32), "wrapped"u8.ToArray());

        await using var ring = await new KeyRingBuilder()
            .WithKeyWrapper(wrapper)
            .WithCryptoProviderFactory(new RecordingCryptoProviderFactory())
            .WithKeyRefreshInterval(60)
            .WithKeyFile(10, "dek.bin")
            .WithEphemeralKey(1)
            .WithoutEphemeralKeyRotation()
            .BuildAsync();

        Assert.Equal(10, ring.CurrentVersion);
        Assert.Null(ring.EphemeralKeyRotationInterval);
    }

    [Fact]
    public async Task Build_WhenTheKeyWrapperRefusesAKeyFile_FailsWithItsReason()
    {
        var wrapper = new ReadingKeyWrapper(RandomNumberGenerator.GetBytes(32), []);
        var refusal = new UnauthorizedAccessException("another account could have replaced it");
        var refusing = new RefusingKeyWrapper(wrapper, refusal);

        var thrown = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new KeyRingBuilder()
            .WithKeyWrapper(refusing)
            .WithCryptoProviderFactory(CryptoProviderFactory)
            .WithKeyRefreshInterval(60)
            .WithKeyFile(1, "dek.bin")
            .BuildAsync());

        Assert.Same(refusal, thrown);
    }

    private sealed class RefusingKeyWrapper(IKeyWrapper inner, Exception refusal) : IKeyWrapper
    {
        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => inner.WrapAsync(plaintext, result, cancellationToken);

        public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
            => inner.UnwrapAsync(wrapped, result, cancellationToken);

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
            => inner.GenerateAndWrapAsync(result, cancellationToken);

        public ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
            => ValueTask.FromException<byte[]>(refusal);
    }

    [Fact]
    public async Task Build_TheBuiltRingOwnsItsProviders()
    {
        var factory = new RecordingCryptoProviderFactory();
        var ring = await new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(factory)
            .WithKeyRefreshInterval(60)
            .WithEphemeralKey(1)
            .BuildAsync();

        ring.Dispose();

        AssertDisposed(Assert.Single(factory.CreatedProviders));
    }

    private static void AssertDisposed(ICryptoProvider provider)
        => Assert.Throws<ObjectDisposedException>(() => provider.Encrypt(new byte[] { 1 }, new byte[64]));

    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    public void WithMaxRefreshFailures_AtLeastOne_SetsMaxRefreshFailures(int maxRefreshFailures)
    {
        var builder = new KeyRingBuilder().WithMaxRefreshFailures(maxRefreshFailures);

        Assert.Equal(maxRefreshFailures, builder.MaxRefreshFailures);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void WithMaxRefreshFailures_BelowOne_Throws(int maxRefreshFailures)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithMaxRefreshFailures(maxRefreshFailures));
    }

    [Fact]
    public void MaxRefreshFailures_DefaultsToFailClosedAfterThree()
    {
        Assert.Equal(3, KeyRingBuilder.DefaultMaxRefreshFailures);
        Assert.Equal(KeyRingBuilder.DefaultMaxRefreshFailures, new KeyRingBuilder().MaxRefreshFailures);
    }

    [Fact]
    public void WithFailOpenOnRefreshFailure_ClearsThePolicy_AndALaterWithMaxRefreshFailuresReplacesIt()
    {
        var builder = new KeyRingBuilder().WithMaxRefreshFailures(5);

        Assert.Same(builder, builder.WithFailOpenOnRefreshFailure());
        Assert.Null(builder.MaxRefreshFailures);

        builder.WithMaxRefreshFailures(2);
        Assert.Equal(2, builder.MaxRefreshFailures);
    }

    [Fact]
    public async Task Build_PassesMaxRefreshFailuresToBothFactoryPaths_DefaultingToFailClosedAfterThree()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var withPolicy = new RecordingCryptoProviderFactory();
            var withoutPolicy = new RecordingCryptoProviderFactory();

            using var _ = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(withPolicy)
                .WithKeyRefreshInterval(60)
                .WithMaxRefreshFailures(5)
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .BuildAsync();
            using var __ = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(withoutPolicy)
                .WithKeyRefreshInterval(60)
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .BuildAsync();
            var failOpen = new RecordingCryptoProviderFactory();
            using var ___ = await new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(failOpen)
                .WithKeyRefreshInterval(60)
                .WithFailOpenOnRefreshFailure()
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .BuildAsync();

            Assert.Equal([5, 5], withPolicy.MaxRefreshFailuresCalls);
            Assert.Equal([KeyRingBuilder.DefaultMaxRefreshFailures, KeyRingBuilder.DefaultMaxRefreshFailures], withoutPolicy.MaxRefreshFailuresCalls);
            Assert.Equal([null, null], failOpen.MaxRefreshFailuresCalls);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static KeyRingBuilder ConfiguredBuilder(ICryptoProviderFactory factory) => new KeyRingBuilder()
        .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
        .WithCryptoProviderFactory(factory)
        .WithKeyRefreshInterval(60);

    [Fact]
    public async Task BuildAsync_ProducesAWorkingRingFromKeyFilesAndEphemeralKeys()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());

            using var ring = await ConfiguredBuilder(CryptoProviderFactory)
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .BuildAsync();

            Assert.Equal(2, ring.CurrentVersion);
            var protector = ring.CreateProtector("purpose");
            var formatted = protector.Encrypt("hello".AsSpan());
            Span<char> result = new char[16];
            Assert.Equal("hello", new string(result[..protector.Decrypt(formatted, result)]));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task BuildAsync_WithMissingConfiguration_ThrowsTheSameErrorsAsBuild()
    {
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KeyRingBuilder().WithCryptoProviderFactory(CryptoProviderFactory).WithKeyRefreshInterval(60).WithEphemeralKey(1).BuildAsync());

        Assert.Equal("A key wrapper is required - call WithKeyWrapper first.", exception.Message);
    }

    [Fact]
    public async Task BuildAsync_WhenAlreadyCancelled_CreatesNothing()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var factory = new RecordingCryptoProviderFactory();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                ConfiguredBuilder(factory).WithKeyFile(1, path).BuildAsync(new CancellationToken(true)));

            Assert.Empty(factory.CreatedProviders);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task BuildAsync_CancelledPartway_DisposesWhatItAlreadyCreated()
    {
        var first = Path.GetTempFileName();
        var second = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(first, "wrapped-1"u8.ToArray());
            File.WriteAllBytes(second, "wrapped-2"u8.ToArray());
            using var cts = new CancellationTokenSource();
            var factory = new RecordingCryptoProviderFactory { AfterEachCreate = cts.Cancel };

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                ConfiguredBuilder(factory).WithKeyFile(1, first).WithKeyFile(2, second).BuildAsync(cts.Token));

            AssertDisposed(Assert.Single(factory.CreatedProviders));
        }
        finally
        {
            File.Delete(first);
            File.Delete(second);
        }
    }
}
