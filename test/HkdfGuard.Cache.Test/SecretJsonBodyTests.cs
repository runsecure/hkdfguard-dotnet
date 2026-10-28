using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Cache.Test;

/// <summary>SecretJsonBody hands a JSON body's secret to a sink and returns the body with it blanked.</summary>
public class SecretJsonBodyTests
{
    private static async Task<FakeRemoteSecretCache> CreateCacheAsync()
        => new(TestRing.For(new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60))), SecretNameMatching.Exact);

    // Runs Capture inside a fetch, as a provider's pipeline does; returns the redacted body and the value cached.
    private static async Task<(string Redacted, byte[] Cached)> CaptureAsync(string body, string text = "value", string? base64 = null)
    {
        var cache = await CreateCacheAsync();
        string? redacted = null;
        cache.OnFetch = (_, sink) => redacted = Encoding.UTF8.GetString(
            SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, text, base64));

        var result = new byte[body.Length + 16];
        var written = cache.Decrypt("item", result);
        return (redacted!, result[..written]);
    }

    [Fact]
    public async Task TheTextValue_IsHandedOver_AndBlankedInTheBody()
    {
        var (redacted, cached) = await CaptureAsync("""{"id":"x","value":"s3cret","n":1}""");

        Assert.Equal("s3cret"u8.ToArray(), cached);
        Assert.Equal("""{"id":"x","value":"","n":1}""", redacted);
    }

    [Fact]
    public async Task TheBase64Value_IsHandedOverDecoded()
    {
        var (redacted, cached) = await CaptureAsync("""{"SecretString":null,"SecretBinary":"AAH+/w=="}""", "SecretString", "SecretBinary");

        Assert.Equal(new byte[] { 0, 1, 254, 255 }, cached);
        Assert.Equal("""{"SecretString":null,"SecretBinary":""}""", redacted);
    }

    [Fact]
    public async Task EscapesAreUnescaped()
    {
        var (_, cached) = await CaptureAsync("""{"value":"a\"b\\cé\n"}""");

        Assert.Equal("a\"b\\cé\n", Encoding.UTF8.GetString(cached));
    }

    [Fact]
    public async Task ANestedPropertyOfTheSameName_IsLeftAlone()
    {
        var (redacted, cached) = await CaptureAsync("""{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":"top"}""");

        Assert.Equal("top"u8.ToArray(), cached);
        Assert.Equal("""{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":""}""", redacted);
    }

    [Theory]
    [InlineData("""{"other":"x"}""")]
    [InlineData("""{"value":null}""")]
    [InlineData("""{"value":42}""")]
    [InlineData("""{"value":""}""")]
    public async Task NoNonEmptyStringValue_HandsNothingOver(string body)
    {
        var (redacted, cached) = await CaptureAsync(body);

        Assert.Empty(cached);
        Assert.Equal(body, redacted);
    }

    [Fact]
    public async Task EmptyDuplicates_AreBlankedAlongsideTheValue()
    {
        var (redacted, cached) = await CaptureAsync("""{"value":"","value":"s","value":""}""");

        Assert.Equal("s"u8.ToArray(), cached);
        Assert.Equal("""{"value":"","value":"","value":""}""", redacted);
    }

    [Theory]
    [InlineData("""{"value":"a","value":"b"}""", "value", null)]
    [InlineData("""{"SecretString":"a","SecretBinary":"Yg=="}""", "SecretString", "SecretBinary")]
    [InlineData("""{"SecretBinary":"not base64!"}""", "SecretString", "SecretBinary")]
    [InlineData("""["value"]""", "value", null)]
    [InlineData("""{"value":"unterminated""", "value", null)]
    [InlineData("", "value", null)]
    public async Task ABodyThatCantBeTrusted_IsRefused_AndNothingIsCached(string body, string text, string? base64)
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, text, base64);

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));

        cache.OnFetch = null;
        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ABodyLargerThanTheFirstBuffer_IsReadWhole()
    {
        var padding = new string('x', 100_000);
        var (redacted, cached) = await CaptureAsync($$"""{"pad":"{{padding}}","value":"s3cret"}""");

        Assert.Equal("s3cret"u8.ToArray(), cached);
        Assert.Equal($$"""{"pad":"{{padding}}","value":""}""", redacted);
    }

    [Fact]
    public async Task ABodyAtTheLimit_IsRefused()
    {
        var cache = await CreateCacheAsync();
        var body = new MemoryStream(new byte[SecretJsonBody.MaxBodyLength]);
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(body, sink, "value");

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ANestedValue_IsHandedOver_AndOnlyItIsBlanked()
    {
        var cache = await CreateCacheAsync();
        string? redacted = null;
        const string body = """{"value":"top","data":{"value":"middle","data":{"other":1,"value":"s3cret"},"metadata":{"value":"m"}}}""";
        cache.OnFetch = (_, sink) => redacted = Encoding.UTF8.GetString(
            SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, ["data", "data"], "value"));

        var result = new byte[64];
        var written = cache.Decrypt("item", result);

        Assert.Equal("s3cret"u8.ToArray(), result[..written]);
        Assert.Equal("""{"value":"top","data":{"value":"middle","data":{"other":1,"value":""},"metadata":{"value":"m"}}}""", redacted);
    }

    [Theory]
    [InlineData("""{"data":null}""")]
    [InlineData("""{"data":"value"}""")]
    [InlineData("""{"data":[{"value":"x"}]}""")]
    [InlineData("""{"other":{"value":"x"}}""")]
    public async Task APathLeadingToNoObject_HandsNothingOver(string body)
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, ["data"], "value");

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ValuesUnderDuplicateParents_AreRefused()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(
            new MemoryStream("""{"data":{"value":"a"},"data":{"value":"b"}}"""u8.ToArray()), sink, ["data"], "value");

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ATextValueHoldingAJsonObject_IsHandedOverWholeAndByKey_ButABase64OneIsNot()
    {
        var cache = await CreateCacheAsync();
        var json = """{"user":"app","pass":"s3cret"}""";
        var body = $$"""{"SecretString":{{System.Text.Json.JsonSerializer.Serialize(json)}}}""";
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, "SecretString", "SecretBinary");

        var result = new byte[64];
        Assert.Equal("s3cret"u8.ToArray(), result[..cache.Decrypt("item#pass", result)]);
        Assert.Equal("app"u8.ToArray(), result[..cache.Decrypt("item#user", result)]);
        Assert.Equal(Encoding.UTF8.GetBytes(json), result[..cache.Decrypt("item", result)]);

        var binary = $$"""{"SecretBinary":"{{Convert.ToBase64String(Encoding.UTF8.GetBytes(json))}}"}""";
        cache.OnFetch = (_, sink) => SecretJsonBody.Capture(new MemoryStream(Encoding.UTF8.GetBytes(binary)), sink, "SecretString", "SecretBinary");
        Assert.Equal(Encoding.UTF8.GetBytes(json), result[..cache.Decrypt("binary", result)]);
        Assert.Equal(0, cache.Decrypt("binary#pass", result));
    }

    [Fact]
    public async Task CaptureKeys_HandsOverEveryMemberOfTheObjectAtThePath()
    {
        var cache = await CreateCacheAsync();
        const string body = """{"data":{"data":{"username":"app","password":"s3cret","port":5432},"metadata":{"version":3}},"value":"top"}""";
        cache.OnFetch = (_, sink) => SecretJsonBody.CaptureKeys(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, ["data", "data"]);

        var result = new byte[64];
        Assert.Equal("s3cret"u8.ToArray(), result[..cache.Decrypt("item#password", result)]);
        Assert.Equal("app"u8.ToArray(), result[..cache.Decrypt("item#username", result)]);
        Assert.Equal("5432"u8.ToArray(), result[..cache.Decrypt("item#port", result)]);
        Assert.Equal(0, cache.Decrypt("item", result));
        Assert.Equal(0, cache.Decrypt("item#version", result));
        Assert.Equal(0, cache.Decrypt("item#value", result));
    }

    [Theory]
    [InlineData("""{"data":{"data":null}}""")]
    [InlineData("""{"data":{"other":{"k":"v"}}}""")]
    [InlineData("""{"data":{"data":{}}}""")]
    public async Task CaptureKeys_WithNoKeysAtThePath_HandsNothingOver(string body)
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) => SecretJsonBody.CaptureKeys(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, ["data", "data"]);

        Assert.Equal(0, cache.Decrypt("item#k", new byte[16]));
    }

    [Theory]
    [InlineData("""{"data":{"k":"a"},"data":{"k":"b"}}""")]
    [InlineData("""{"data":{"k":"a","k":"b"}}""")]
    [InlineData("""{"data":{"k":"a",}}""")]
    [InlineData("""["data"]""")]
    public async Task CaptureKeys_RefusesABodyThatCantBeTrusted_AndCachesNothing(string body)
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) => SecretJsonBody.CaptureKeys(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, ["data"]);

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item#k", new byte[16]));
    }

    [Fact]
    public async Task CaptureKeys_ChecksItsArguments()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) =>
        {
            Assert.Throws<ArgumentNullException>(() => SecretJsonBody.CaptureKeys(null!, sink, ["data"]));
            Assert.Throws<ArgumentNullException>(() => SecretJsonBody.CaptureKeys(new MemoryStream(), null!, ["data"]));
            Assert.Throws<ArgumentException>(() => SecretJsonBody.CaptureKeys(new MemoryStream(), sink, [""]));
        };

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task CaptureAsync_HandsTheValueOver_AndReturnsTheBodyBlanked()
    {
        var cache = await CreateCacheAsync();
        string? redacted = null;
        var padding = new string('x', 100_000);
        var body = $$"""{"pad":"{{padding}}","value":"{\"k\":\"s3cret\"}"}""";
        cache.OnFetchAsync = async (_, sink, cancellationToken) => redacted = Encoding.UTF8.GetString(
            await SecretJsonBody.CaptureAsync(new MemoryStream(Encoding.UTF8.GetBytes(body)), sink, "value", cancellationToken: cancellationToken));

        var result = new byte[64];
        Assert.Equal("s3cret"u8.ToArray(), result[..await cache.DecryptAsync("item#k", result.AsMemory())]);
        Assert.Equal($$"""{"pad":"{{padding}}","value":""}""", redacted);
    }

    [Fact]
    public async Task CaptureKeysAsync_HandsOverEveryMemberOfTheObjectAtThePath()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetchAsync = (_, sink, cancellationToken) => new ValueTask(SecretJsonBody.CaptureKeysAsync(
            new MemoryStream("""{"data":{"data":{"password":"s3cret"}}}"""u8.ToArray()), sink, ["data", "data"], cancellationToken));

        var result = new byte[64];
        Assert.Equal("s3cret"u8.ToArray(), result[..await cache.DecryptAsync("item#password", result.AsMemory())]);
    }

    [Fact]
    public async Task CaptureAsync_RefusesABodyAtTheLimit()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetchAsync = (_, sink, _) => new ValueTask(SecretJsonBody.CaptureAsync(new MemoryStream(new byte[SecretJsonBody.MaxBodyLength]), sink, "value"));

        await Assert.ThrowsAsync<InvalidDataException>(() => cache.DecryptAsync("item", new byte[16].AsMemory()).AsTask());
    }

    [Fact]
    public async Task CaptureAsync_IsCancelledWithItsToken()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetchAsync = (_, sink, _) => new ValueTask(SecretJsonBody.CaptureAsync(new MemoryStream("{}"u8.ToArray()), sink, "value",
            cancellationToken: new CancellationToken(canceled: true)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cache.DecryptAsync("item", new byte[16].AsMemory()).AsTask());
    }

    [Fact]
    public async Task TheAsyncArguments_AreChecked()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetchAsync = async (_, sink, _) =>
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() => SecretJsonBody.CaptureAsync(null!, sink, "value"));
            await Assert.ThrowsAsync<ArgumentNullException>(() => SecretJsonBody.CaptureAsync(new MemoryStream(), null!, "value"));
            await Assert.ThrowsAsync<ArgumentException>(() => SecretJsonBody.CaptureAsync(new MemoryStream(), sink, ""));
            await Assert.ThrowsAsync<ArgumentNullException>(() => SecretJsonBody.CaptureKeysAsync(new MemoryStream(), sink, null!));
            await Assert.ThrowsAsync<ArgumentException>(() => SecretJsonBody.CaptureKeysAsync(new MemoryStream(), sink, [""]));
        };

        Assert.Equal(0, await cache.DecryptAsync("item", new byte[16].AsMemory()));
    }

    [Fact]
    public async Task TheArguments_AreChecked()
    {
        var cache = await CreateCacheAsync();
        cache.OnFetch = (_, sink) =>
        {
            Assert.Throws<ArgumentNullException>(() => SecretJsonBody.Capture(null!, sink, "value"));
            Assert.Throws<ArgumentNullException>(() => SecretJsonBody.Capture(new MemoryStream(), null!, "value"));
            Assert.Throws<ArgumentException>(() => SecretJsonBody.Capture(new MemoryStream(), sink, ""));
            Assert.Throws<ArgumentException>(() => SecretJsonBody.Capture(new MemoryStream(), sink, ["data", ""], "value"));
            Assert.Throws<ArgumentException>(() => SecretJsonBody.Capture(new MemoryStream(), sink, [null!], "value"));
        };

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }
}
