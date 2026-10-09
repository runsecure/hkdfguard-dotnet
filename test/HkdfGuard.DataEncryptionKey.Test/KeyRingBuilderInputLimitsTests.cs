using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// KeyRingBuilder's input limits: a key file must be 1 to WrappedKeyLimits.MaxBytes bytes, and a
/// service name must follow ServiceNames.
/// </summary>
public class KeyRingBuilderInputLimitsTests
{
    private static KeyRingBuilder Builder(ICryptoProviderFactory? factory = null) => new KeyRingBuilder()
        .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
        .WithCryptoProviderFactory(factory ?? new AesGcmCryptoProviderFactory())
        .WithCachedKeyExpiry(60);

    private static async Task<T> WithKeyFileAsync<T>(int length, Func<string, Task<T>> test)
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, RandomNumberGenerator.GetBytes(length));
            return await test(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TheLimit_IsFiveHundredTwelveBytes()
    {
        Assert.Equal(512, WrappedKeyLimits.MaxBytes);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(156)]                       // today's macOS payload
    [InlineData(WrappedKeyLimits.MaxBytes)] // the limit itself
    public async Task KeyFilesUpToTheLimit_AreReadWhole(int length)
    {
        var factory = new RecordingCryptoProviderFactory();

        var wrapped = await WithKeyFileAsync(length, async path =>
        {
            using var _ = await Builder(factory).WithKeyFile(1, path).BuildAsync();
            return await File.ReadAllBytesAsync(path);
        });

        Assert.Equal(length, Assert.Single(factory.CreatedWrapped).Length);
        Assert.Equal(wrapped, factory.CreatedWrapped[0]);
    }

    [Theory]
    [InlineData(WrappedKeyLimits.MaxBytes + 1)]
    [InlineData(10 * 1024 * 1024)]
    public async Task KeyFilesOverTheLimit_AreRefused(int length)
    {
        var ex = await WithKeyFileAsync(length, path =>
            Assert.ThrowsAsync<InvalidDataException>(() => Builder().WithKeyFile(1, path).BuildAsync()));

        Assert.Contains($"larger than {WrappedKeyLimits.MaxBytes} bytes", ex.Message);
    }

    [Fact]
    public async Task AnEmptyKeyFile_IsRefused()
    {
        var ex = await WithKeyFileAsync(0, path =>
            Assert.ThrowsAsync<InvalidDataException>(() => Builder().WithKeyFile(1, path).BuildAsync()));

        Assert.Contains("is empty", ex.Message);
    }

    [Theory]
    [InlineData(".service")]
    [InlineData("my..service")]
    [InlineData("my-service")]
    [InlineData("")]
    public void WithServiceName_RejectsAnInvalidName(string serviceName)
    {
        var builder = new KeyRingBuilder();

        Assert.Throws<ArgumentException>(() => builder.WithServiceName(serviceName));
        Assert.Null(builder.ServiceName);
    }

    [Fact]
    public void WithServiceName_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyRingBuilder().WithServiceName(null!));
    }
}
