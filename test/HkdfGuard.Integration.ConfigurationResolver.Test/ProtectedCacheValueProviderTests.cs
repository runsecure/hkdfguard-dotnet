using System.Security.Cryptography;
using System.Text;
using ConfigurationResolver.Builders;
using ConfigurationResolver.Exceptions;
using ConfigurationResolver.Interfaces;
using ConfigurationResolver.Providers;
using ConfigurationResolver.Readers;
using ConfigurationResolver.Resolvers;
using ConfigurationResolver.Tokens;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Integration.ConfigurationResolver.Test;

public class ProtectedCacheValueProviderTests
{
    private static async Task<KeyRing> CreateRingAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        return TestRing.For(key);
    }

    private static async Task<ProtectedCache> CreateCacheAsync(params (string Name, string Value)[] values)
    {
        var cache = new ProtectedCache(await CreateRingAsync());
        foreach (var (name, value) in values)
            cache.Add(name, value.ToCharArray());
        return cache;
    }

    private static IConfigurationResolver CreateResolver(string template, IProtectedReadOnlyCache cache)
    {
        var token = new DefaultToken();
        var reader = new ConfigurationItemReader(token);
        reader.ReadKeys(template);
        return new ConfigurationItemResolver(token, reader, new ProtectedCacheValueProvider(cache));
    }

    [Fact]
    public async Task Resolve_Chars_ReplacesItemsWithCachedValues()
    {
        var cache = await CreateCacheAsync(("db-user", "app"), ("db-password", "s3cret"));
        const string template = "User=${db-user};Password=${db-password}";

        var destination = new char[256];
        var written = CreateResolver(template, cache).Resolve(template, destination);

        Assert.Equal("User=app;Password=s3cret", new string(destination, 0, written));
    }

    [Fact]
    public async Task Resolve_Utf8_ReplacesItemsWithCachedValues()
    {
        var cache = await CreateCacheAsync(("db-password", "pässword"));
        var template = "Password=${db-password}"u8;

        var destination = new byte[256];
        var written = CreateResolver("Password=${db-password}", cache).Resolve(template, destination);

        Assert.Equal("Password=pässword", Encoding.UTF8.GetString(destination, 0, written));
    }

    [Fact]
    public async Task Resolve_MissingName_ThrowsNotFound()
    {
        var cache = await CreateCacheAsync(("present", "value"));
        const string template = "${absent}";

        var ex = Assert.Throws<ConfigurationKeyException>(() => CreateResolver(template, cache).Resolve(template, new char[64]));

        Assert.Equal(ConfigurationKeyError.NotFound, ex.Error);
    }

    // The cache's bound is the ciphertext's length, so a destination with exactly the value's room is
    // below it: the value goes through a scratch buffer, small enough for the stack or not.
    [Theory]
    [InlineData(5)]
    [InlineData(ArrayUtility.MaxStackBytes + 100)]
    public async Task Resolve_Chars_DestinationBelowBoundButValueFits_Resolves(int valueLength)
    {
        var value = new string('v', valueLength);
        var cache = await CreateCacheAsync(("item", value));
        const string template = "${item}";

        var destination = new char[valueLength];
        var written = CreateResolver(template, cache).Resolve(template, destination);

        Assert.Equal(value, new string(destination, 0, written));
    }

    [Theory]
    [InlineData(5)]
    [InlineData(ArrayUtility.MaxStackBytes + 100)]
    public async Task Resolve_Utf8_DestinationBelowBoundButValueFits_Resolves(int valueLength)
    {
        var value = new string('v', valueLength);
        var cache = await CreateCacheAsync(("item", value));

        var destination = new byte[valueLength];
        var written = CreateResolver("${item}", cache).Resolve("${item}"u8, destination);

        Assert.Equal(value, Encoding.UTF8.GetString(destination, 0, written));
    }

    [Fact]
    public async Task Resolve_Chars_ValueLargerThanDestination_ThrowsAndWipesDestination()
    {
        var cache = await CreateCacheAsync(("item", "too long a value"));
        const string template = "${item}";
        var destination = new char[4];

        Assert.Throws<ArgumentException>(() => CreateResolver(template, cache).Resolve(template, destination));

        Assert.All(destination, c => Assert.Equal('\0', c));
    }

    [Fact]
    public async Task Resolve_Utf8_ValueLargerThanDestination_ThrowsAndWipesDestination()
    {
        var cache = await CreateCacheAsync(("item", "too long a value"));
        var destination = new byte[4];

        Assert.Throws<ArgumentException>(() => CreateResolver("${item}", cache).Resolve("${item}"u8, destination));

        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task TryGetValue_ByDefault_Throws()
    {
        var provider = new ProtectedCacheValueProvider(await CreateCacheAsync(("item", "value")));

        Assert.Throws<InvalidOperationException>(() => provider.TryGetValue("item", out _));
    }

    [Fact]
    public async Task TryGetValue_WhenAllowed_ReturnsTheValueAsAString()
    {
        var provider = new ProtectedCacheValueProvider(await CreateCacheAsync(("item", "value"))) { AllowStringValues = true };

        Assert.Equal(ValueStatus.Found, provider.TryGetValue("item", out var value));
        Assert.Equal("value", value);
        Assert.Equal(ValueStatus.NotFound, provider.TryGetValue("absent", out value));
        Assert.Null(value);
    }

    [Fact]
    public async Task CompositeValueProvider_FallsThroughToTheNextProviderForMissingNames()
    {
        var cache = await CreateCacheAsync(("db-password", "s3cret"));
        var plain = new DictionaryValueProvider(new Dictionary<string, string> { ["db-host"] = "db.internal" });
        const string template = "Host=${db-host};Password=${db-password}";

        var token = new DefaultToken();
        var reader = new ConfigurationItemReader(token);
        reader.ReadKeys(template);
        var resolver = new ConfigurationItemResolver(token, reader, new ProtectedCacheValueProvider(cache), plain);

        var destination = new char[256];
        var written = resolver.Resolve(template, destination);

        Assert.Equal("Host=db.internal;Password=s3cret", new string(destination, 0, written));
    }

    [Fact]
    public async Task AddProtectedCache_AddsAProviderOverTheCache()
    {
        var cache = await CreateCacheAsync(("db-password", "s3cret"));
        const string template = "Password=${db-password}";
        var token = new DefaultToken();
        var reader = new ConfigurationItemReader(token);
        reader.ReadKeys(template);

        var resolver = new ConfigurationResolverBuilder()
            .WithToken(token)
            .WithReader(reader)
            .AddProtectedCache(cache)
            .Build();

        var destination = new char[64];
        var written = resolver.Resolve(template, destination);

        Assert.Equal("Password=s3cret", new string(destination, 0, written));
    }

    [Fact]
    public async Task PrefetchAsync_FetchesEachKeyOnceWithoutBlocking_SoResolveDoesNotFetch()
    {
        var cache = new FakeRemoteSecretCache(await CreateRingAsync(), SecretNameMatching.Exact)
        {
            // Hands the value over itself, so a blocking Fetch would show up in Fetches.
            OnFetchAsync = (name, sink, _) =>
            {
                if (name == "app-config")
                    sink.SetBytesWithJsonKeys(Encoding.UTF8.GetBytes("""{"user":"app","password":"s3cret"}"""));
                return ValueTask.CompletedTask;
            },
        };
        const string template = "User=${app-config#user};Password=${app-config#password};Again=${app-config#user}";
        var token = new DefaultToken();
        var reader = new ConfigurationItemReader(token);
        reader.ReadKeys(template);
        var provider = new ProtectedCacheValueProvider(cache);

        await provider.PrefetchAsync(reader);

        var destination = new char[256];
        var written = new ConfigurationItemResolver(token, reader, provider).Resolve(template, destination);

        Assert.Equal("User=app;Password=s3cret;Again=app", new string(destination, 0, written));
        Assert.Single(cache.AsyncFetches);
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public async Task PrefetchAsync_SkipsKeysTheCacheDoesNotHave()
    {
        var cache = new FakeRemoteSecretCache(await CreateRingAsync(), SecretNameMatching.Exact);
        cache.Set("present", "value");
        var provider = new ProtectedCacheValueProvider(cache);

        await provider.PrefetchAsync(["present", "absent", "absent"]);

        Assert.Equal(["present", "absent"], cache.AsyncFetches);
        Assert.Equal(ValueStatus.NotFound, provider.TryGetChar("absent", new char[16], out var written));
        Assert.Equal(0, written);
        Assert.Equal(ValueStatus.NotFound, provider.TryGetBytes("absent", new byte[16], out written));
        Assert.Equal(0, written);
    }

    [Fact]
    public async Task PrefetchAsync_Cancelled_Throws()
    {
        var cache = new FakeRemoteSecretCache(await CreateRingAsync(), SecretNameMatching.Exact);
        var provider = new ProtectedCacheValueProvider(cache);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.PrefetchAsync(["item"], new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task Members_RejectNullArguments()
    {
        var cache = await CreateCacheAsync();
        var provider = new ProtectedCacheValueProvider(cache);

        Assert.Same(cache, provider.Cache);
        Assert.Throws<ArgumentNullException>(() => new ProtectedCacheValueProvider(null!));
        Assert.Throws<ArgumentNullException>(() => provider.TryGetBytes(null!, new byte[1], out _));
        Assert.Throws<ArgumentNullException>(() => provider.TryGetChar(null!, new char[1], out _));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.PrefetchAsync((IConfigurationItemReader)null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => provider.PrefetchAsync((IEnumerable<string>)null!));
        Assert.Throws<ArgumentNullException>(() => ((IConfigurationResolverBuilder)null!).AddProtectedCache(cache));
        Assert.Throws<ArgumentNullException>(() => new ConfigurationResolverBuilder().AddProtectedCache(null!));
    }
}
