using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>Names holding a key ("secret#key"): one fetch caching a secret's keys, and SecretValueSink's key setters.</summary>
public class SecretKeysTests
{
    // A key/value secret as AWS Secrets Manager's console stores one.
    private const string KeyValueSecret = """
        {
          "test-credential-1": "This is my first credential",
          "service-credential-3": "This is my third credential",
          "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
          "domain-credential-17": "fakedomain/thiscredential"
        }
        """;

    private static async Task<FakeRemoteSecretCache> CreateAsync(SecretNameMatching matching = SecretNameMatching.Exact)
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))), matching);

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[512];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    private static void SetJson(SecretValueSink sink, string json) => sink.SetBytesWithJsonKeys(Encoding.UTF8.GetBytes(json));

    [Fact]
    public async Task OneFetch_CachesTheWholeValueAndEveryKey()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, KeyValueSecret);

        Assert.Equal("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==", DecryptString(cache, "creds#api-credential-21"));
        Assert.Equal("This is my first credential", DecryptString(cache, "creds#test-credential-1"));
        Assert.Equal("This is my third credential", DecryptString(cache, "creds#service-credential-3"));
        Assert.Equal("fakedomain/thiscredential", DecryptString(cache, "creds#domain-credential-17"));
        Assert.Equal(KeyValueSecret, DecryptString(cache, "creds"));

        Assert.Equal(["creds"], cache.Fetches);
    }

    [Fact]
    public async Task ConcurrentMissesOnDifferentKeys_ShareOneFetch()
    {
        var cache = await CreateAsync();
        using var release = new ManualResetEventSlim();
        cache.OnFetch = (_, sink) =>
        {
            release.Wait(TimeSpan.FromSeconds(10));
            SetJson(sink, """{"a":"1","b":"2","c":"3"}""");
        };

        var lookups = new[] { "s#a", "s#b", "s#c", "s" }.Select(name => Task.Run(() => DecryptString(cache, name))).ToArray();
        await Task.Delay(200);
        release.Set();

        Assert.Equal(["1", "2", "3", """{"a":"1","b":"2","c":"3"}"""], await Task.WhenAll(lookups));
        Assert.Single(cache.Fetches);
    }

    [Fact]
    public async Task AKeyTheSecretDoesntHold_IsMissing_AndFetchesAgain_WithoutReplacingWhatIsCached()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, """{"a":"first"}""");
        Assert.Equal("first", DecryptString(cache, "s#a"));

        Assert.Equal(0, cache.Decrypt("s#b", new byte[16]));

        cache.OnFetch = (_, sink) => SetJson(sink, """{"a":"second","b":"added"}""");
        Assert.Equal("added", DecryptString(cache, "s#b"));
        Assert.Equal("first", DecryptString(cache, "s#a"));
        Assert.Equal(3, cache.Fetches.Count);
    }

    [Fact]
    public async Task KeysAreMatchedExactly_EvenWhereSecretNamesIgnoreCase()
    {
        var cache = await CreateAsync(SecretNameMatching.IgnoreAsciiCase);
        cache.OnFetch = (_, sink) => SetJson(sink, """{"Key":"upper","key":"lower"}""");

        Assert.Equal("upper", DecryptString(cache, "Db#Key"));
        Assert.Equal("lower", DecryptString(cache, "DB#key"));
        Assert.Equal("upper", DecryptString(cache, "db#Key"));
        Assert.Equal(0, cache.Decrypt("db#KEY", new byte[16]));

        Assert.Equal(["Db", "db"], cache.Fetches);
    }

    [Fact]
    public async Task UnderExactMatching_SecretNamesAndKeysAreBothExact()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (name, sink) => SetJson(sink, $$"""{"Pass":"{{name}}"}""");

        Assert.Equal("Prod/Db", DecryptString(cache, "Prod/Db#Pass"));
        Assert.Equal("prod/db", DecryptString(cache, "prod/db#Pass"));
        Assert.Equal(0, cache.Decrypt("prod/db#pass", new byte[16]));
    }

    [Theory]
    [InlineData("s#")]
    [InlineData("s#a#b")]
    [InlineData("s#a b")]
    [InlineData("s#bang!")]
    [InlineData("s#café")]
    [InlineData("#key")]
    [InlineData("in:valid#key")]
    public async Task ANameWhoseSecretOrKeyIsntOne_IsMissing_WithoutAFetch(string name)
    {
        var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.False(cache.TryGetMaxDecryptedLength(name, out _));
        Assert.Empty(cache.Fetches);
    }

    [Fact]
    public void IsValidKey_AcceptsPrintableAsciiButSpaceBangAndHash_UpToTheLimit()
    {
        Assert.True(RemoteSecretCache.IsValidKey("a"));
        Assert.True(RemoteSecretCache.IsValidKey("ConnectionStrings:Admin"));
        Assert.True(RemoteSecretCache.IsValidKey("\"$%&'()*+,-./0-9;<=>?@A-Z[\\]^_`a-z{|}~"));
        Assert.True(RemoteSecretCache.IsValidKey(new string('k', RemoteSecretCache.MaxKeyLength)));
        Assert.False(RemoteSecretCache.IsValidKey(new string('k', RemoteSecretCache.MaxKeyLength + 1)));
        Assert.False(RemoteSecretCache.IsValidKey(null));
        Assert.False(RemoteSecretCache.IsValidKey(""));
        Assert.False(RemoteSecretCache.IsValidKey("a b"));
        Assert.False(RemoteSecretCache.IsValidKey("a!"));
        Assert.False(RemoteSecretCache.IsValidKey("a#"));
        Assert.False(RemoteSecretCache.IsValidKey("tab\t"));
        Assert.False(RemoteSecretCache.IsValidKey("del\u007f"));
    }

    [Fact]
    public async Task WithADefaultKey_ANameWithoutOne_ReadsThatKey_NotTheWholeValue()
    {
        var cache = await CreateAsync();
        cache.DefaultKeyToRead = "value";
        cache.OnFetch = (_, sink) =>
        {
            sink.SetText("the whole value");
            sink.SetKeyBytes("value", "the default key"u8.ToArray());
            sink.SetKeyBytes("other", "another key"u8.ToArray());
        };

        Assert.Equal("the default key", DecryptString(cache, "s"));
        Assert.Equal("the default key", DecryptString(cache, "s#value"));
        Assert.Equal("another key", DecryptString(cache, "s#other"));
        Assert.Single(cache.Fetches);
    }

    [Fact]
    public async Task SetKeyBytes_ZeroesWhatItsGiven_AndRefusesAnInvalidKey()
    {
        var cache = await CreateAsync();
        var given = new byte[] { 1, 2, 3 };
        var refused = new byte[] { 4, 5, 6 };
        cache.OnFetch = (_, sink) =>
        {
            Assert.Throws<ArgumentException>(() => sink.SetKeyBytes("not a key", refused));
            Assert.Throws<ArgumentException>(() => sink.SetKeyBytes(null!, refused));
            sink.SetKeyBytes("k", given);
        };

        var result = new byte[16];
        Assert.Equal(new byte[] { 1, 2, 3 }, result[..cache.Decrypt("s#k", result)]);
        Assert.All(given, b => Assert.Equal(0, b));
        Assert.All(refused, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task SettingAKeyTwice_Throws_AndNothingIsCached()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) =>
        {
            sink.SetKeyBytes("k", "first"u8.ToArray());
            sink.SetText("whole");
            sink.SetKeyBytes("k", "second"u8.ToArray());
        };

        Assert.Throws<InvalidOperationException>(() => cache.Decrypt("s#k", new byte[16]));

        cache.OnFetch = null;
        Assert.Equal(0, cache.Decrypt("s", new byte[16]));
        Assert.Equal(0, cache.Decrypt("s#k", new byte[16]));
    }

    [Fact]
    public async Task AnEmptyKey_IsMissing_AndCanStillBeSetAfterwards()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) =>
        {
            sink.SetKeyBytes("k", []);
            sink.SetKeyBytes("k", "set"u8.ToArray());
        };

        Assert.Equal("set", DecryptString(cache, "s#k"));
    }

    [Fact]
    public async Task ASinkKeptPastItsFetch_RefusesKeys()
    {
        var cache = await CreateAsync();
        SecretValueSink? kept = null;
        cache.OnFetch = (_, sink) => kept = sink;
        Assert.Equal(0, cache.Decrypt("s#k", new byte[16]));

        var bytes = new byte[] { 9 };
        Assert.Throws<InvalidOperationException>(() => kept!.SetKeyBytes("k", bytes));
        Assert.Equal(0, bytes[0]);
        var json = """{"k":"v"}"""u8.ToArray();
        Assert.Throws<InvalidOperationException>(() => kept!.SetBytesWithJsonKeys(json));
        Assert.All(json, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task JsonMembers_AreCachedAsTheirText_OrLeftOut()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, """
            {"text":"a\"b\\cé\n","int":3306,"real":-1.5e3,"yes":true,"no":false,
             "null":null,"object":{"x":"y"},"array":["z"],"empty":"","bad key":"x","bang!":"x","Ascaped":"name"}
            """);

        Assert.Equal("a\"b\\cé\n", DecryptString(cache, "s#text"));
        Assert.Equal("3306", DecryptString(cache, "s#int"));
        Assert.Equal("-1.5e3", DecryptString(cache, "s#real"));
        Assert.Equal("true", DecryptString(cache, "s#yes"));
        Assert.Equal("false", DecryptString(cache, "s#no"));
        Assert.Equal("name", DecryptString(cache, "s#Ascaped"));
        foreach (var key in new[] { "null", "object", "array", "empty", "x" })
            Assert.Equal(0, cache.Decrypt($"s#{key}", new byte[16]));
    }

    [Theory]
    [InlineData("plain text")]
    [InlineData("""["a","b"]""")]
    [InlineData("\"a json string\"")]
    [InlineData("42")]
    [InlineData("""{"k":"unterminated""")]
    [InlineData("""{"k":"v"} trailing""")]
    [InlineData("""{"k":"v"}{"k":"w"}""")]
    [InlineData("{\"k\":\"v\", // a comment\n\"j\":\"w\"}")]
    public async Task AValueThatIsntOneJsonObject_IsCachedWholeOnly(string value)
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, value);

        Assert.Equal(value, DecryptString(cache, "s"));
        Assert.Equal(0, cache.Decrypt("s#k", new byte[16]));
        Assert.Equal(0, cache.Decrypt("s#a", new byte[16]));
    }

    [Fact]
    public async Task AJsonObjectWithWhitespaceAround_IsSplit()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, "  \r\n{\"k\":\"v\"}\n  ");

        Assert.Equal("v", DecryptString(cache, "s#k"));
    }

    [Fact]
    public async Task ADuplicatedKey_IsRefused_AndNothingIsCached()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => SetJson(sink, """{"dup-key-name":"a","other":"b","dup-key-name":"c"}""");

        // The key is part of a name, which is logged only with sensitive logging on; an error log carries the message.
        var e = Assert.Throws<InvalidDataException>(() => cache.Decrypt("s#other", new byte[16]));
        Assert.DoesNotContain("dup-key-name", e.Message, StringComparison.Ordinal);

        cache.OnFetch = null;
        Assert.Equal(0, cache.Decrypt("s", new byte[16]));
    }

    [Fact]
    public async Task SetBytesWithJsonKeys_ZeroesWhatItsGiven()
    {
        var cache = await CreateAsync();
        var given = """{"k":"v"}"""u8.ToArray();
        cache.OnFetch = (_, sink) => sink.SetBytesWithJsonKeys(given);

        Assert.Equal("v", DecryptString(cache, "s#k"));
        Assert.All(given, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task AnEmptyValue_WithJsonKeys_IsMissing()
    {
        var cache = await CreateAsync();
        cache.OnFetch = (_, sink) => sink.SetBytesWithJsonKeys([]);

        Assert.Equal(0, cache.Decrypt("s", new byte[16]));
    }
}
