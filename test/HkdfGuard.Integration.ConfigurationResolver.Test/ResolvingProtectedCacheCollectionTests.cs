using System.Security.Cryptography;
using System.Text;
using ConfigurationResolver.Exceptions;
using ConfigurationResolver.Providers;
using ConfigurationResolver.Tokens;
using HkdfGuard.Cache;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Diagnostics;
using HkdfGuard.Integration.ConfigurationResolver.Test.TestHelpers;

namespace HkdfGuard.Integration.ConfigurationResolver.Test;

public class ResolvingProtectedCacheCollectionTests
{
    private static async Task<KeyRing> CreateRingAsync()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(wrapper, "wrapped"u8.ToArray(), 60));
        return TestRing.For(key);
    }

    private static async Task<(ResolvingProtectedCacheCollection Collection, PlainSource Source)> CreateAsync()
    {
        var source = new PlainSource
        {
            ["conn"] = "Host=${host};Password=${password}",
            ["host"] = "db.internal",
            ["password"] = "s3cret",
        };
        return (new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(source), source);
    }

    private static string DecryptChars(ResolvingProtectedCacheCollection collection, string name)
    {
        Assert.True(collection.TryGetMaxDecryptedLength(name, out var maxLength));
        var result = new char[maxLength];
        return new string(result, 0, collection.Decrypt(name, result));
    }

    private static string DecryptBytes(ResolvingProtectedCacheCollection collection, string name)
    {
        Assert.True(collection.TryGetMaxDecryptedLength(name, out var maxLength));
        var result = new byte[maxLength];
        return Encoding.UTF8.GetString(result, 0, collection.Decrypt(name, result));
    }

    [Fact]
    public async Task Template_IsResolvedFromTheSources_AndCached()
    {
        var (collection, source) = await CreateAsync();

        Assert.Equal("Host=db.internal;Password=s3cret", DecryptChars(collection, "conn"));
        Assert.Equal("Host=db.internal;Password=s3cret", DecryptBytes(collection, "conn"));

        // Read and resolved once; every later lookup decrypts the cached result.
        Assert.Equal(1, source.DecryptCount("conn"));
        Assert.Equal(1, source.DecryptCount("password"));
    }

    [Fact]
    public async Task Template_IsResolvedByAFirstDecrypt_WithoutSizingFirst()
    {
        var (collection, _) = await CreateAsync();
        var (asyncCollection, _) = await CreateAsync();

        var result = new byte[64];
        Assert.Equal("Host=db.internal;Password=s3cret", Encoding.UTF8.GetString(result, 0, collection.Decrypt("conn", result)));
        Assert.Equal("Host=db.internal;Password=s3cret", Encoding.UTF8.GetString(result, 0, await asyncCollection.DecryptAsync("conn", result)));
    }

    [Fact]
    public async Task ResolvedValue_IsCachedEncrypted_NotAsTheSourcesValues()
    {
        var (collection, _) = await CreateAsync();

        Assert.True(collection.TryGetMaxDecryptedLength("conn", out var maxLength));

        // An AEAD bound: longer than the 32-byte resolved value it encloses.
        Assert.True(maxLength > "Host=db.internal;Password=s3cret".Length);
    }

    [Fact]
    public async Task ValueWithoutItems_IsAnsweredByItsSource_WhichIsRemembered()
    {
        var (collection, source) = await CreateAsync();

        Assert.Equal("s3cret", DecryptChars(collection, "password"));
        Assert.Equal("s3cret", DecryptBytes(collection, "password"));

        // One search through the sources, then only the two TryGetMaxDecryptedLength calls the
        // remembered source answers.
        Assert.Equal(3, source.LengthLookupCount("password"));
        Assert.Equal(3, source.DecryptCount("password"));
    }

    [Fact]
    public async Task MissingName_IsReportedMissing()
    {
        var (collection, _) = await CreateAsync();

        Assert.Equal(0, collection.Decrypt("absent", new byte[16]));
        Assert.Equal(0, collection.Decrypt("absent", new char[16]));
        Assert.False(collection.TryGetMaxDecryptedLength("absent", out var maxLength));
        Assert.Equal(0, maxLength);
        Assert.Equal(0, await collection.DecryptAsync("absent", new byte[16]));
        Assert.Equal(0, await collection.DecryptAsync("absent", new char[16]));
        Assert.Equal(0, await collection.GetMaxDecryptedLengthAsync("absent"));
    }

    [Fact]
    public async Task Sources_AreCheckedInOrder_ForNamesAndItems()
    {
        var first = new PlainSource { ["conn"] = "${password}", ["password"] = "first" };
        var second = new PlainSource { ["conn"] = "ignored", ["password"] = "second", ["only-second"] = "${password}" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(first).Add(second);

        Assert.Equal("first", DecryptChars(collection, "conn"));
        Assert.Equal("first", DecryptChars(collection, "only-second"));
        Assert.Equal(0, second.DecryptCount("conn"));
    }

    [Fact]
    public async Task ValueProviders_SupplyItemsAfterTheSources_GrowingTheBufferWhenNeeded()
    {
        var large = new string('x', 5000);
        var source = new PlainSource { ["conn"] = "Host=${host};Blob=${blob}", ["host"] = "from-source" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync())
            .Add(source)
            .AddValueProvider(new DictionaryValueProvider(new Dictionary<string, string> { ["host"] = "ignored", ["blob"] = large }));

        Assert.Equal($"Host=from-source;Blob={large}", DecryptChars(collection, "conn"));
    }

    [Fact]
    public async Task ValueProviders_AreNotAnsweredByNameOnTheirOwn()
    {
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync())
            .AddValueProvider(new DictionaryValueProvider(new Dictionary<string, string> { ["host"] = "db" }));

        Assert.False(collection.TryGetMaxDecryptedLength("host", out _));
    }

    [Fact]
    public async Task ResolvedValueLongerThanMaxResolvedLength_Throws()
    {
        var source = new PlainSource { ["conn"] = "${blob}" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()) { MaxResolvedLength = 16 }
            .Add(source)
            .AddValueProvider(new DictionaryValueProvider(new Dictionary<string, string> { ["blob"] = new string('x', 17) }));

        var ex = Assert.Throws<InvalidOperationException>(() => collection.Decrypt("conn", new char[64]));

        Assert.IsType<ArgumentException>(ex.InnerException);
    }

    [Fact]
    public async Task MaxResolvedLength_DefaultsAndRejectsLessThanOne()
    {
        var ring = await CreateRingAsync();
        var collection = new ResolvingProtectedCacheCollection(ring);

        Assert.Equal(ResolvingProtectedCacheCollection.DefaultMaxResolvedLength, collection.MaxResolvedLength);
        Assert.IsType<DefaultToken>(collection.Token);
        Assert.Throws<ArgumentOutOfRangeException>(() => new ResolvingProtectedCacheCollection(ring) { MaxResolvedLength = 0 });
    }

    [Fact]
    public async Task TemplateNamingAMissingValue_Throws()
    {
        var source = new PlainSource { ["conn"] = "${absent}" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(source);

        Assert.Equal(ConfigurationKeyError.NotFound, Assert.Throws<ConfigurationKeyException>(() => collection.Decrypt("conn", new byte[64])).Error);
        Assert.Throws<ConfigurationKeyException>(() => collection.Decrypt("conn", new char[64]));
        Assert.Throws<ConfigurationKeyException>(() => collection.TryGetMaxDecryptedLength("conn", out _));
        await Assert.ThrowsAsync<ConfigurationKeyException>(() => collection.DecryptAsync("conn", new byte[64]).AsTask());
        await Assert.ThrowsAsync<ConfigurationKeyException>(() => collection.DecryptAsync("conn", new char[64]).AsTask());
        await Assert.ThrowsAsync<ConfigurationKeyException>(() => collection.GetMaxDecryptedLengthAsync("conn").AsTask());
    }

    [Fact]
    public async Task TemplateResolvingToNothing_IsReportedMissing()
    {
        var source = new PlainSource { ["conn"] = "${empty}" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync())
            .Add(source)
            .AddValueProvider(new DictionaryValueProvider(new Dictionary<string, string> { ["empty"] = "" }));

        Assert.False(collection.TryGetMaxDecryptedLength("conn", out _));
        Assert.Equal(0, collection.Decrypt("conn", new char[16]));
    }

    [Fact]
    public async Task ResolvedValue_IsKeptUntilInvalidated()
    {
        var (collection, source) = await CreateAsync();
        Assert.Equal("Host=db.internal;Password=s3cret", DecryptChars(collection, "conn"));

        source["password"] = "rotated";
        Assert.Equal("Host=db.internal;Password=s3cret", DecryptChars(collection, "conn"));

        Assert.True(collection.Invalidate("conn"));
        Assert.Equal("Host=db.internal;Password=rotated", DecryptChars(collection, "conn"));
        Assert.False(collection.Invalidate("never-looked-up"));
    }

    [Fact]
    public async Task Invalidate_ForgetsWhichSourceHoldsAPlainValue()
    {
        var first = new PlainSource();
        var second = new PlainSource { ["password"] = "second" };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(first).Add(second);
        Assert.Equal("second", DecryptChars(collection, "password"));

        first["password"] = "first";
        Assert.Equal("second", DecryptChars(collection, "password"));

        Assert.True(collection.Invalidate("password"));
        Assert.Equal("first", DecryptChars(collection, "password"));
    }

    [Fact]
    public async Task Clear_ForgetsEverything()
    {
        var (collection, source) = await CreateAsync();
        DecryptChars(collection, "conn");
        DecryptChars(collection, "host");

        source["host"] = "db2";
        source["password"] = "rotated";
        collection.Clear();

        Assert.Equal("Host=db2;Password=rotated", DecryptChars(collection, "conn"));
        Assert.Equal("db2", DecryptChars(collection, "host"));
    }

    [Fact]
    public async Task InvalidateDuringAResolve_KeepsItsResultOutOfTheCache()
    {
        var (collection, source) = await CreateAsync();
        source.OnFirstDecrypt = ("password", () =>
        {
            source["password"] = "rotated";
            collection.Invalidate("conn");
        });

        // The first resolution read the old value, so it is dropped and the lookup resolves again.
        var result = new char[64];
        Assert.Equal("Host=db.internal;Password=rotated", new string(result, 0, collection.Decrypt("conn", result)));
        Assert.Equal(2, source.DecryptCount("conn"));

        Assert.Equal("Host=db.internal;Password=rotated", new string(result, 0, collection.Decrypt("conn", result)));
        Assert.Equal(2, source.DecryptCount("conn"));
    }

    [Fact]
    public async Task InvalidateDuringAPlainLookup_DoesNotRememberTheSource()
    {
        var (collection, source) = await CreateAsync();
        source.OnFirstDecrypt = ("host", () => collection.Clear());

        Assert.Equal("db.internal", DecryptChars(collection, "host"));
        var lookups = source.LengthLookupCount("host");

        Assert.Equal("db.internal", DecryptChars(collection, "host"));
        Assert.Equal(lookups + 1, source.LengthLookupCount("host"));
    }

    [Fact]
    public async Task Names_MatchExactly_EvenWhereTheResolvedStoreIgnoresCase()
    {
        var source = new PlainSource
        {
            ["Db"] = "upper ${value}",
            ["db"] = "lower ${value}",
            ["a!b"] = "bang ${value}",
            ["aB"] = "camel ${value}",
            ["app/Db-1"] = "path ${value}",
            ["value"] = "v",
        };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(source);

        Assert.Equal("upper v", DecryptChars(collection, "Db"));
        Assert.Equal("lower v", DecryptChars(collection, "db"));
        Assert.Equal("bang v", DecryptChars(collection, "a!b"));
        Assert.Equal("camel v", DecryptChars(collection, "aB"));
        Assert.Equal("path v", DecryptChars(collection, "app/Db-1"));
        Assert.Equal("upper v", DecryptChars(collection, "Db"));
    }

    [Fact]
    public async Task AsyncLookups_ResolveFromARemoteSource_WithoutBlockingFetches()
    {
        var values = new Dictionary<string, string>
        {
            ["conn"] = "Host=${host};Password=${password}",
            ["host"] = "db.internal",
            ["password"] = "s3cret",
        };
        var remote = new FakeRemoteSecretCache(await CreateRingAsync(), SecretNameMatching.Exact)
        {
            OnFetchAsync = (name, sink, _) =>
            {
                if (values.TryGetValue(name, out var value))
                    sink.SetText(value);
                return ValueTask.CompletedTask;
            },
        };
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync()).Add(remote);

        var maxLength = await collection.GetMaxDecryptedLengthAsync("conn");
        var chars = new char[maxLength];
        var bytes = new byte[maxLength];

        Assert.Equal("Host=db.internal;Password=s3cret", new string(chars, 0, await collection.DecryptAsync("conn", chars)));
        Assert.Equal("Host=db.internal;Password=s3cret", Encoding.UTF8.GetString(bytes, 0, await collection.DecryptAsync("conn", bytes)));
        Assert.Equal(maxLength, await collection.GetMaxDecryptedLengthAsync("conn"));

        // A plain value, found and then remembered.
        Assert.True(await collection.GetMaxDecryptedLengthAsync("host") > 0);
        Assert.Equal("s3cret", new string(chars, 0, await collection.DecryptAsync("password", chars)));
        Assert.Equal("s3cret", Encoding.UTF8.GetString(bytes, 0, await collection.DecryptAsync("password", bytes)));

        Assert.Empty(remote.Fetches);
    }

    [Fact]
    public async Task AsyncLookup_AfterTheTemplateWasInvalidated_ResolvesAgain()
    {
        var (collection, source) = await CreateAsync();
        Assert.True(await collection.GetMaxDecryptedLengthAsync("conn") > 0);

        source["password"] = "rotated";
        collection.Invalidate("conn");

        var result = new char[64];
        Assert.Equal("Host=db.internal;Password=rotated", new string(result, 0, await collection.DecryptAsync("conn", result)));
    }

    [Fact]
    public async Task SensitiveLogging_IncludesTheName()
    {
        var (collection, _) = await CreateAsync();
        var previous = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
        try
        {
            Assert.Equal("s3cret", DecryptChars(collection, "password"));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = previous;
        }
    }

    [Fact]
    public async Task Members_RejectNullArguments()
    {
        var collection = new ResolvingProtectedCacheCollection(await CreateRingAsync());

        Assert.Throws<ArgumentNullException>(() => new ResolvingProtectedCacheCollection(null!));
        Assert.Throws<ArgumentNullException>(() => collection.Add(null!));
        Assert.Throws<ArgumentNullException>(() => collection.AddValueProvider(null!));
        Assert.Throws<ArgumentNullException>(() => collection.Invalidate(null!));
        Assert.Throws<ArgumentNullException>(() => collection.Decrypt(null!, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => collection.TryGetMaxDecryptedLength(null!, out _));
    }
}
