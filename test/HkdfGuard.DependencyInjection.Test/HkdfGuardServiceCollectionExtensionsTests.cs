using System.Security.Cryptography;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DependencyInjection.Test.TestHelpers;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection.Test;

public class HkdfGuardServiceCollectionExtensionsTests
{
    private static KeyRingBuilder Configure(KeyRingBuilder builder) => Configure(builder, version: 1);

    private static KeyRingBuilder Configure(KeyRingBuilder builder, int version)
        => builder
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .WithEphemeralKey(version);

    [Fact]
    public async Task AddKeyRingAsync_ReturnsTheSameServiceCollectionForChaining()
    {
        var services = new ServiceCollection();

        var returned = await services.AddKeyRingAsync(Configure);

        Assert.Same(services, returned);
    }

    [Fact]
    public async Task AddKeyRingAsync_BuildsTheRingAtRegistration_BeforeTheContainerExists()
    {
        var invoked = false;
        var services = new ServiceCollection();

        await services.AddKeyRingAsync(builder =>
        {
            invoked = true;
            return Configure(builder);
        });

        Assert.True(invoked);
    }

    [Fact]
    public async Task AddKeyRingAsync_RegistersKeyRingAsASingleton()
    {
        var services = new ServiceCollection();
        await services.AddKeyRingAsync(Configure);

        await using var provider = services.BuildServiceProvider();
        var ring1 = provider.GetRequiredService<KeyRing>();
        var ring2 = provider.GetRequiredService<KeyRing>();

        Assert.Same(ring1, ring2);
    }

    [Fact]
    public async Task AddKeyRingAsync_ResolvesAWorkingKeyRing()
    {
        var services = new ServiceCollection();
        await services.AddKeyRingAsync(Configure);

        await using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("hello".AsSpan());
        var result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result, 0, written));
    }

    [Fact]
    public async Task AddKeyRingAsync_CalledTwice_KeepsTheFirstRegistration_WithoutBuildingTheSecond()
    {
        var secondInvoked = false;
        var services = new ServiceCollection();
        await services.AddKeyRingAsync(Configure);
        await services.AddKeyRingAsync(builder =>
        {
            secondInvoked = true;
            return Configure(builder, version: 2);
        });

        await using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        Assert.Equal(1, ring.CurrentVersion);
        Assert.False(secondInvoked);
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(KeyRing));
    }

    [Fact]
    public async Task AddKeyRingAsync_TheContainerDisposesTheRingAtShutdown()
    {
        var services = new ServiceCollection();
        await services.AddKeyRingAsync(Configure);

        var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();
        var protector = ring.CreateProtector("purpose");

        await provider.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => protector.Encrypt("hello".AsSpan()));
    }

    [Fact]
    public async Task AddKeyRingAsync_WhenTheBuildFails_RegistersNothing()
    {
        var services = new ServiceCollection();

        // No key files or ephemeral keys: BuildAsync rejects the configuration.
        await Assert.ThrowsAsync<InvalidOperationException>(() => services.AddKeyRingAsync(builder => builder
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)));

        Assert.Empty(services);
    }

    [Fact]
    public async Task AddKeyRingAsync_WhenAlreadyCancelled_Throws_AndRegistersNothing()
    {
        var services = new ServiceCollection();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            services.AddKeyRingAsync(Configure, new CancellationToken(true)));

        Assert.Empty(services);
    }

    [Fact]
    public async Task AddKeyRingAsync_WithNullArguments_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            HkdfGuardServiceCollectionExtensions.AddKeyRingAsync(null!, Configure));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            new ServiceCollection().AddKeyRingAsync(null!));
    }

    [Fact]
    public async Task AddKeyRingAsync_AlsoRegistersTheRingAsIKeyRing_SoACacheCanResolveIt()
    {
        var services = new ServiceCollection();
        await services.AddKeyRingAsync(Configure);
        services.AddSingleton<HkdfGuard.Cache.ProtectedCache>();

        await using var provider = services.BuildServiceProvider();

        Assert.Same(provider.GetRequiredService<KeyRing>(), provider.GetRequiredService<HkdfGuard.Abstractions.IKeyRing>());
        var cache = provider.GetRequiredService<HkdfGuard.Cache.ProtectedCache>();
        cache.Add("item", "value"u8.ToArray());
        Assert.Equal(5, cache.Decrypt("item", new byte[16]));
    }
}
