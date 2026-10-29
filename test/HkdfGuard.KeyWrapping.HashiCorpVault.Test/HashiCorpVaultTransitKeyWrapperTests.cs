using System.Net;
using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.KeyWrapping.HashiCorpVault.Test.TestHelpers;
using HkdfGuard.SecureFile;

namespace HkdfGuard.KeyWrapping.HashiCorpVault.Test;

public class HashiCorpVaultTransitKeyWrapperTests
{
    private const string Context = "hkdfguard.test";

    private static readonly string ContextBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(Context));

    private static HashiCorpVaultTransitKeyWrapper Create(FakeTransit vault, string? context = Context, IVaultTokenSource? tokens = null,
        string keyName = FakeTransit.KeyName, KeyFileTrust? keyFileTrust = null, HashiCorpVaultTransitKeyWrapperOptions? options = null)
        => new(FakeTransit.Address, keyName, tokens ?? new FakeTokenSource(), context, keyFileTrust,
            options is null
                ? new HashiCorpVaultTransitKeyWrapperOptions { HttpMessageHandler = vault, RetryDelay = TimeSpan.Zero }
                : new HashiCorpVaultTransitKeyWrapperOptions
                {
                    HttpMessageHandler = vault,
                    MountPath = options.MountPath,
                    Namespace = options.Namespace,
                    Timeout = options.Timeout,
                    RetryCount = options.RetryCount,
                    RetryDelay = options.RetryDelay,
                });

    private static async Task<byte[]> WrapAsync(HashiCorpVaultTransitKeyWrapper wrapper, byte[] dek)
    {
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        return wrapped[..await wrapper.WrapAsync(dek, wrapped)];
    }

    private static async Task<byte[]> GenerateAsync(HashiCorpVaultTransitKeyWrapper wrapper)
    {
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        return wrapped[..await wrapper.GenerateAndWrapAsync(wrapped)];
    }

    [Fact]
    public void Constructor_RejectsMissingArguments()
    {
        var tokens = new FakeTokenSource();

        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultTransitKeyWrapper(null!, FakeTransit.KeyName, tokens));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, null!, tokens));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, FakeTransit.KeyName, null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("team/kek")]
    [InlineData("my kek")]
    [InlineData("kek?x=1")]
    [InlineData("kék")]
    public void Constructor_RejectsAKeyNameThatIsNotOne(string keyName)
        => Assert.Throws<ArgumentException>("keyName", () => new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, keyName, new FakeTokenSource()));

    [Fact]
    public void Constructor_RejectsAKeyNameOverTheLimit()
        => Assert.Throws<ArgumentException>("keyName", () => new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address,
            new string('k', HashiCorpVaultTransitKeyWrapper.MaxKeyNameLength + 1), new FakeTokenSource()));

    [Theory]
    [InlineData("http://vault.example.com:8200")]
    [InlineData("https://user:pass@vault.example.com:8200")]
    [InlineData("https://vault.example.com:8200/?x=1")]
    [InlineData("https://vault.example.com:8200/#f")]
    [InlineData("ftp://vault.example.com")]
    public void Constructor_RejectsAnAddressThatWouldExposeTheTokenOrDeks(string address)
        => Assert.Throws<ArgumentException>("address", () => new HashiCorpVaultTransitKeyWrapper(new Uri(address), FakeTransit.KeyName, new FakeTokenSource()));

    [Fact]
    public void Constructor_RejectsARelativeAddress()
        => Assert.Throws<ArgumentException>("address", () =>
            new HashiCorpVaultTransitKeyWrapper(new Uri("vault", UriKind.Relative), FakeTransit.KeyName, new FakeTokenSource()));

    [Theory]
    [InlineData("http://127.0.0.1:8200")]
    [InlineData("http://localhost:8200")]
    [InlineData("http://[::1]:8200")]
    public void Constructor_AllowsHttpOnLoopback(string address)
        => new HashiCorpVaultTransitKeyWrapper(new Uri(address), FakeTransit.KeyName, new FakeTokenSource()).Dispose();

    [Fact]
    public void Constructor_RejectsAContextOverTheLimit()
        => Assert.Throws<ArgumentException>("context", () => new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, FakeTransit.KeyName,
            new FakeTokenSource(), new string('c', HashiCorpVaultTransitKeyWrapper.MaxContextLength + 1)));

    public static TheoryData<HashiCorpVaultTransitKeyWrapperOptions> BadOptions => new()
    {
        new HashiCorpVaultTransitKeyWrapperOptions { MountPath = "" },
        new HashiCorpVaultTransitKeyWrapperOptions { MountPath = "transit/../sys" },
        new HashiCorpVaultTransitKeyWrapperOptions { MountPath = "/transit" },
        new HashiCorpVaultTransitKeyWrapperOptions { Namespace = "team a" },
        new HashiCorpVaultTransitKeyWrapperOptions { HttpMessageHandler = new SocketsHttpHandler() },
        new HashiCorpVaultTransitKeyWrapperOptions { HttpMessageHandler = new LoggingHandler(new HttpClientHandler()) },
    };

    [Theory]
    [MemberData(nameof(BadOptions))]
    public void Constructor_RejectsOptionsThatAreNotOnes(HashiCorpVaultTransitKeyWrapperOptions options)
        => Assert.Throws<ArgumentException>("options", () =>
            new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, FakeTransit.KeyName, new FakeTokenSource(), options: options));

    public static TheoryData<HashiCorpVaultTransitKeyWrapperOptions> OutOfRangeOptions => new()
    {
        new HashiCorpVaultTransitKeyWrapperOptions { Timeout = TimeSpan.Zero },
        new HashiCorpVaultTransitKeyWrapperOptions { RetryCount = HashiCorpVaultTransitKeyWrapperOptions.MinRetryCount - 1 },
        new HashiCorpVaultTransitKeyWrapperOptions { RetryCount = HashiCorpVaultTransitKeyWrapperOptions.MaxRetryCount + 1 },
        new HashiCorpVaultTransitKeyWrapperOptions { RetryDelay = TimeSpan.FromMilliseconds(-1) },
        new HashiCorpVaultTransitKeyWrapperOptions { RetryDelay = HashiCorpVaultTransitKeyWrapperOptions.MaxRetryDelay + TimeSpan.FromTicks(1) },
    };

    [Theory]
    [MemberData(nameof(OutOfRangeOptions))]
    public void Constructor_RejectsOptionsOutOfRange(HashiCorpVaultTransitKeyWrapperOptions options)
        => Assert.Throws<ArgumentOutOfRangeException>("options", () =>
            new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, FakeTransit.KeyName, new FakeTokenSource(), options: options));

    [Fact]
    public void Constructor_AcceptsARedirectingHandler_OnlyWithAllowRedirects()
    {
        using var handler = new SocketsHttpHandler();
        new HashiCorpVaultTransitKeyWrapper(FakeTransit.Address, FakeTransit.KeyName, new FakeTokenSource(),
            options: new HashiCorpVaultTransitKeyWrapperOptions { HttpMessageHandler = handler, AllowRedirects = true }).Dispose();
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTripsTheDek()
    {
        using var wrapper = Create(new FakeTransit());
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await WrapAsync(wrapper, dek);
        var revealed = new byte[32];

        Assert.StartsWith("vault:v1:", Encoding.ASCII.GetString(wrapped));
        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped, revealed));
        Assert.Equal(dek, revealed);
    }

    [Fact]
    public async Task WrapAsync_EncryptsUnderTheKeyWithTheContext_AndZeroesWhatItSent()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);
        var dek = RandomNumberGenerator.GetBytes(32);

        await WrapAsync(wrapper, dek);

        var request = Assert.Single(vault.Requests);
        Assert.Equal(("encrypt", FakeTransit.KeyName), (request.Operation, request.Key));
        Assert.Equal(Convert.ToBase64String(dek), request.Field("plaintext"));
        Assert.Equal(ContextBase64, request.Field("associated_data"));
        Assert.Equal(2, request.Json.Count);
        Assert.Equal(FakeTransit.Token, request.Token);
        Assert.Null(request.Namespace);
        Assert.All(Assert.Single(vault.BodyMemory).ToArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(vault.TokenHeaders), c => Assert.Equal('\0', c));
        Assert.False(vault.AnyResponseBuffered);
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public async Task UnwrapAsync_DecryptsUnderTheKeyWithTheContext()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);
        var wrapped = await WrapAsync(wrapper, RandomNumberGenerator.GetBytes(32));

        await wrapper.UnwrapAsync(wrapped, new byte[32]);

        var request = vault.Requests.Last();
        Assert.Equal(("decrypt", FakeTransit.KeyName), (request.Operation, request.Key));
        Assert.Equal(Encoding.ASCII.GetString(wrapped), request.Field("ciphertext"));
        Assert.Equal(ContextBase64, request.Field("associated_data"));
        Assert.False(vault.AnyResponseBuffered);
    }

    [Fact]
    public async Task GenerateAndWrapAsync_WithNoContext_HasVaultGenerateAWrappedAes256KeyOnly()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault, context: null);

        var wrapped = await GenerateAsync(wrapper);
        var revealed = new byte[32];
        var revealedLength = await wrapper.UnwrapAsync(wrapped, revealed);

        var requests = vault.Requests.ToArray();
        Assert.Equal(("datakey", FakeTransit.KeyName), (requests[0].Operation, requests[0].Key));
        Assert.Equal("""{"bits":256}""", Encoding.UTF8.GetString(requests[0].Body));
        Assert.Null(requests[1].Field("associated_data"));
        Assert.Equal(HashiCorpVaultTransitKeyWrapper.GeneratedKeyLength, revealedLength);
        Assert.False(revealed.All(b => b == 0));
    }

    [Fact]
    public async Task WithAnEmptyContext_SendsNone()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault, context: "");

        var wrapped = await WrapAsync(wrapper, RandomNumberGenerator.GetBytes(32));
        await wrapper.UnwrapAsync(wrapped, new byte[32]);
        await GenerateAsync(wrapper);

        Assert.All(vault.Requests, r => Assert.Null(r.Field("associated_data")));
        Assert.Equal("datakey", vault.Requests.Last().Operation);
    }

    [Fact]
    public async Task GenerateAndWrapAsync_WithAContext_GeneratesHere_AndEncryptsWithIt()
    {
        // datakey/wrapped ignores associated_data, so it can't bind a context.
        var vault = new FakeTransit();
        using var wrapper = Create(vault);

        var wrapped = await GenerateAsync(wrapper);
        var revealed = new byte[32];
        await wrapper.UnwrapAsync(wrapped, revealed);

        var request = vault.Requests.First();
        Assert.Equal("encrypt", request.Operation);
        Assert.Equal(ContextBase64, request.Field("associated_data"));
        Assert.Equal(Convert.FromBase64String(request.Field("plaintext")!), revealed);
        Assert.False(revealed.All(b => b == 0));
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherKey_FailsAndZeroesTheResult()
    {
        var vault = new FakeTransit();
        vault.AddKey("other-kek");
        using var other = Create(vault, keyName: "other-kek");
        var wrapped = await WrapAsync(other, RandomNumberGenerator.GetBytes(32));

        using var wrapper = Create(vault);
        var result = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await wrapper.UnwrapAsync(wrapped, result));

        Assert.Equal($"Vault transit unwrap failed for key '{FakeTransit.KeyName}': Vault answered 400 BadRequest: cipher: message authentication failed",
            exception.Message);
        Assert.Equal(HttpStatusCode.BadRequest, Assert.IsType<HttpRequestException>(exception.InnerException).StatusCode);
        Assert.All(result, b => Assert.Equal(0, b));
        Assert.Equal(2, vault.Requests.Count);
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherContext_Fails()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);
        using var other = Create(vault, context: "other");
        using var none = Create(vault, context: null);
        var wrapped = await WrapAsync(wrapper, RandomNumberGenerator.GetBytes(32));

        await Assert.ThrowsAsync<CryptographicException>(async () => await other.UnwrapAsync(wrapped, new byte[32]));
        await Assert.ThrowsAsync<CryptographicException>(async () => await none.UnwrapAsync(wrapped, new byte[32]));
    }

    [Fact]
    public async Task UnwrapAsync_WhenTampered_Fails()
    {
        using var wrapper = Create(new FakeTransit());
        var wrapped = await WrapAsync(wrapper, RandomNumberGenerator.GetBytes(32));
        // Another base64 character, so it still reaches Vault and fails there.
        wrapped[12] = wrapped[12] == (byte)'A' ? (byte)'B' : (byte)'A';

        await Assert.ThrowsAsync<CryptographicException>(async () => await wrapper.UnwrapAsync(wrapped, new byte[32]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("vault:v1:")]
    [InlineData("vault:v:AAAA")]
    [InlineData("vault:x1:AAAA")]
    [InlineData("vault:v12345678901:AAAA")]
    [InlineData("vault:v1:AA\"},\"x\":\"AA")]
    [InlineData("vault:v1:AA AA")]
    [InlineData("VAULT:v1:AAAA")]
    public async Task UnwrapAsync_OfSomethingThatIsNotACiphertext_FailsWithoutCallingVault(string wrapped)
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);

        await Assert.ThrowsAsync<CryptographicException>(async () => await wrapper.UnwrapAsync(Encoding.UTF8.GetBytes(wrapped), new byte[32]));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task UnwrapAsync_OverTheKeyFileLimit_FailsWithoutCallingVault()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);
        var wrapped = Encoding.ASCII.GetBytes("vault:v1:" + new string('A', WrappedKeyLimits.MaxBytes));

        await Assert.ThrowsAsync<CryptographicException>(async () => await wrapper.UnwrapAsync(wrapped, new byte[32]));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task UnwrapAsync_WhenTheKeyDoesNotFit_FailsAndZeroesTheResult()
    {
        using var wrapper = Create(new FakeTransit());
        var wrapped = await WrapAsync(wrapper, RandomNumberGenerator.GetBytes(32));

        var result = Enumerable.Repeat((byte)0xAA, 16).ToArray();
        await Assert.ThrowsAsync<ArgumentException>("result", async () => await wrapper.UnwrapAsync(wrapped, result));

        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(HashiCorpVaultTransitKeyWrapper.MaxPlaintextLength + 1)]
    public async Task WrapAsync_RejectsAPlaintextOutOfBounds(int size)
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);

        await Assert.ThrowsAsync<ArgumentException>("plaintext", async () =>
            await wrapper.WrapAsync(new byte[size], new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task WrapAsync_OfTheLargestPlaintext_FitsTheKeyFileLimit()
    {
        using var wrapper = Create(new FakeTransit());
        var dek = RandomNumberGenerator.GetBytes(HashiCorpVaultTransitKeyWrapper.MaxPlaintextLength);

        var wrapped = await WrapAsync(wrapper, dek);
        var revealed = new byte[dek.Length];

        Assert.Equal(dek.Length, await wrapper.UnwrapAsync(wrapped, revealed));
        Assert.Equal(dek, revealed);
    }

    [Fact]
    public async Task WrapAsync_WhenResultIsTooSmall_Throws()
    {
        using var wrapper = Create(new FakeTransit());

        await Assert.ThrowsAsync<ArgumentException>("result", async () => await wrapper.WrapAsync(new byte[32], new byte[8]));
    }

    public static TheoryData<string, string> BadAnswers => new()
    {
        { "not JSON", "<html>proxy</html>" },
        { "not an object", "[]" },
        { "no data", FakeTransit.Envelope(null!) },
        { "data not an object", """{"data":"x"}""" },
        { "no ciphertext", FakeTransit.Envelope(new { key_version = 1 }) },
        { "ciphertext not a string", FakeTransit.Envelope(new { ciphertext = 7 }) },
        { "ciphertext empty", FakeTransit.Envelope(new { ciphertext = "" }) },
        { "ciphertext twice", """{"data":{"ciphertext":"vault:v1:AAAA","ciphertext":"vault:v1:BBBB"}}""" },
        { "not a ciphertext", FakeTransit.Envelope(new { ciphertext = "AAAA" }) },
        { "over the key file limit", FakeTransit.Envelope(new { ciphertext = "vault:v1:" + new string('A', WrappedKeyLimits.MaxBytes) }) },
        { "a parameter ignored", FakeTransit.Envelope(new { ciphertext = "vault:v1:AAAA" }, ["Endpoint ignored these unrecognized parameters: [associated_data]"]) },
    };

    [Theory]
    [MemberData(nameof(BadAnswers))]
    public async Task WrapAsync_RefusesAnAnswerThatIsNotACiphertext(string because, string body)
    {
        _ = because;
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.OK, body) };
        using var wrapper = Create(vault);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.WrapAsync(new byte[32], new byte[2 * WrappedKeyLimits.MaxBytes]));

        Assert.Single(vault.Requests);
    }

    [Fact]
    public async Task AnEscapedAnswer_IsUnescaped()
    {
        // vault:v1:AB+/ with '+' as a \u escape and '/' as \/, as a proxy re-encoding the answer might write it.
        const char backslash = '\\';
        var body = "{\"data\":{\"ciphertext\":\"vault:v1:AB" + backslash + "u002B" + backslash + "/\"}}";
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.OK, body) };
        using var wrapper = Create(vault);

        Assert.Equal("vault:v1:AB+/"u8.ToArray(), await WrapAsync(wrapper, new byte[32]));
    }

    [Fact]
    public async Task AnAnswerWithOtherWarnings_IsAccepted()
    {
        var vault = new FakeTransit
        {
            Answer = (_, _) => (HttpStatusCode.OK, """{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":[7,{"unrecognized parameters":1},"some other warning"]}"""),
        };
        using var wrapper = Create(vault);

        Assert.Equal("vault:v1:AAAA"u8.ToArray(), await WrapAsync(wrapper, new byte[32]));
    }

    [Fact]
    public async Task AVaultThatIgnoresTheContext_IsRefused_RatherThanWrappingUnbound()
    {
        var vault = new FakeTransit { IgnoresAssociatedData = true };
        using var wrapper = Create(vault);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await GenerateAsync(wrapper));

        Assert.Contains("ignored a parameter", exception.Message);
    }

    [Theory]
    [InlineData("""{"data":{"plaintext":"not base64!"}}""")]
    [InlineData("""{"data":{"plaintext":"AAA"}}""")]
    [InlineData("""{"data":{}}""")]
    public async Task UnwrapAsync_RefusesAnAnswerThatIsNotAPlaintext_AndZeroesTheResult(string body)
    {
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.OK, body) };
        using var wrapper = Create(vault);

        var result = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        await Assert.ThrowsAsync<CryptographicException>(async () => await wrapper.UnwrapAsync("vault:v1:AAAA"u8.ToArray(), result));

        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task AnAnswerOverTheResponseLimit_IsRefused()
    {
        var huge = FakeTransit.Envelope(new { ciphertext = "vault:v1:AAAA", padding = new string('x', HashiCorpVaultTransitKeyWrapper.MaxResponseLength) });
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.OK, huge) };
        using var wrapper = Create(vault);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await WrapAsync(wrapper, new byte[32]));

        Assert.Contains("over", exception.Message);
        Assert.Single(vault.Requests);
    }

    [Fact]
    public async Task AnAnswerOfExactlyTheResponseLimit_IsRead()
    {
        var body = FakeTransit.Envelope(new { ciphertext = "vault:v1:AAAA", padding = "" });
        body = body.Replace("\"padding\":\"\"", $"\"padding\":\"{new string('x', HashiCorpVaultTransitKeyWrapper.MaxResponseLength - body.Length)}\"");
        Assert.Equal(HashiCorpVaultTransitKeyWrapper.MaxResponseLength, body.Length);
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.OK, body) };
        using var wrapper = Create(vault);

        Assert.Equal("vault:v1:AAAA"u8.ToArray(), await WrapAsync(wrapper, new byte[32]));
    }

    [Fact]
    public async Task AVaultRefusal_BecomesACryptographicExceptionNamingVaultsErrors_AndIsNotRetried()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault, tokens: new FakeTokenSource { Next = (_, _) => ValueTask.FromResult("hvs.revoked") });

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await WrapAsync(wrapper, new byte[32]));

        Assert.Equal($"Vault transit wrap failed for key '{FakeTransit.KeyName}': Vault answered 403 Forbidden: 1 error occurred:\n\t* permission denied\n\n",
            exception.Message);
        Assert.Equal(HttpStatusCode.Forbidden, Assert.IsType<HttpRequestException>(exception.InnerException).StatusCode);
        Assert.Single(vault.Requests);
    }

    [Theory]
    [InlineData("<html>bad gateway</html>")]
    [InlineData("""{"errors":"x"}""")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task ARefusalThatIsNotVaultsJson_IsReportedByItsStatus(string body)
    {
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.NotFound, body) };
        using var wrapper = Create(vault);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await GenerateAsync(wrapper));

        Assert.EndsWith("Vault answered 404 NotFound", exception.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task ATransientFailure_IsRetried_AskingForTheTokenOnce(HttpStatusCode status)
    {
        var vault = new FakeTransit { Answer = (_, count) => count <= 2 ? (status, """{"errors":["Vault is sealed"]}""") : null };
        var tokens = new FakeTokenSource();
        using var wrapper = Create(vault, tokens: tokens);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await WrapAsync(wrapper, dek);

        Assert.Equal(3, vault.Requests.Count);
        Assert.Equal(1, tokens.Calls);
        Assert.All(vault.TokenHeaders, header => Assert.All(header, c => Assert.Equal('\0', c)));
        var revealed = new byte[32];
        await wrapper.UnwrapAsync(wrapped, revealed);
        Assert.Equal(dek, revealed);
    }

    [Fact]
    public async Task ATransientFailure_ThatOutlastsTheRetries_BecomesACryptographicException()
    {
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.ServiceUnavailable, """{"errors":["Vault is sealed"]}""") };
        using var wrapper = Create(vault, options: new HashiCorpVaultTransitKeyWrapperOptions { RetryCount = 4, RetryDelay = TimeSpan.Zero });

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await GenerateAsync(wrapper));

        Assert.Equal(5, vault.Requests.Count);
        Assert.EndsWith("Vault answered 503 ServiceUnavailable: Vault is sealed", exception.Message);
    }

    [Fact]
    public async Task NotImplemented_IsNotRetried()
    {
        var vault = new FakeTransit { Answer = (_, _) => (HttpStatusCode.NotImplemented, """{"errors":[]}""") };
        using var wrapper = Create(vault);

        await Assert.ThrowsAsync<CryptographicException>(async () => await GenerateAsync(wrapper));

        Assert.Single(vault.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ALostConnection_IsRetried(bool midResponse)
    {
        var failures = 0;
        var vault = new FakeTransit
        {
            OnRequest = _ => failures++ >= 1 ? Task.CompletedTask
                : midResponse ? throw new IOException("connection reset mid-response") : throw new HttpRequestException("connection reset"),
        };
        using var wrapper = Create(vault);

        await GenerateAsync(wrapper);

        Assert.Equal(2, vault.Requests.Count);
    }

    [Fact]
    public async Task AnAttemptThatTimesOut_IsRetried_ThenReportedAsNoAnswer()
    {
        var vault = new FakeTransit { OnRequest = cancellationToken => Task.Delay(Timeout.Infinite, cancellationToken) };
        using var wrapper = Create(vault, options: new HashiCorpVaultTransitKeyWrapperOptions
        {
            Timeout = TimeSpan.FromMilliseconds(50),
            RetryDelay = TimeSpan.Zero,
        });

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () => await GenerateAsync(wrapper));

        Assert.Equal(HashiCorpVaultTransitKeyWrapperOptions.MinRetryCount + 1, vault.Requests.Count);
        Assert.Contains("no answer within", exception.Message);
        Assert.IsAssignableFrom<OperationCanceledException>(exception.InnerException);
    }

    [Fact]
    public async Task Cancellation_IsNotWrapped_OrRetried()
    {
        using var cts = new CancellationTokenSource();
        var vault = new FakeTransit
        {
            OnRequest = async cancellationToken =>
            {
                await cts.CancelAsync();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            },
        };
        using var wrapper = Create(vault);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes], cts.Token));

        Assert.Single(vault.Requests);
    }

    [Fact]
    public async Task CancellationBeforeTheCall_IsNotWrapped()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes], cts.Token));

        Assert.Empty(vault.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("hvs.with space")]
    [InlineData("hvs.é")]
    [InlineData("hvs.\n")]
    public async Task ATokenThatIsNotOne_FailsWithoutARequest(string token)
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault, tokens: new FakeTokenSource { Next = (_, _) => ValueTask.FromResult(token) });

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await GenerateAsync(wrapper));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task ATokenOverTheLimit_FailsWithoutARequest()
    {
        var vault = new FakeTransit();
        var token = new string('t', HashiCorpVaultTransitKeyWrapper.MaxTokenLength + 1);
        using var wrapper = Create(vault, tokens: new FakeTokenSource { Next = (_, _) => ValueTask.FromResult(token) });

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await GenerateAsync(wrapper));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task ATokenSourcesFailure_PropagatesAsItIs()
    {
        var vault = new FakeTransit();
        using var wrapper = Create(vault, tokens: new FakeTokenSource { Next = (_, _) => throw new TimeoutException("login failed") });

        await Assert.ThrowsAsync<TimeoutException>(async () => await GenerateAsync(wrapper));

        Assert.Empty(vault.Requests);
    }

    [Fact]
    public async Task TheTokenSource_IsGivenTheTimeout()
    {
        var vault = new FakeTransit();
        var tokens = new FakeTokenSource
        {
            Next = async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return FakeTransit.Token;
            },
        };
        using var wrapper = Create(vault, tokens: tokens, options: new HashiCorpVaultTransitKeyWrapperOptions { Timeout = TimeSpan.FromMilliseconds(50) });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await GenerateAsync(wrapper));
    }

    [Fact]
    public async Task StaticVaultTokenSource_SuppliesItsToken_UntilDisposed()
    {
        var vault = new FakeTransit();
        var tokens = new StaticVaultTokenSource(FakeTransit.Token);
        using var wrapper = Create(vault, tokens: tokens);

        await GenerateAsync(wrapper);
        tokens.Dispose();

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await GenerateAsync(wrapper));
        Assert.Single(vault.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("hvs.with space")]
    [InlineData("hvs.é")]
    public void StaticVaultTokenSource_RejectsATokenThatIsNotOne(string token)
        => Assert.Throws<ArgumentException>("token", () => new StaticVaultTokenSource(token));

    [Fact]
    public async Task StaticVaultTokenSource_RejectsATokenOverTheLimit_AndADestinationTooSmall()
    {
        Assert.Throws<ArgumentException>("token", () => new StaticVaultTokenSource(new string('t', HashiCorpVaultTransitKeyWrapper.MaxTokenLength + 1)));

        using var tokens = new StaticVaultTokenSource(FakeTransit.Token);
        await Assert.ThrowsAsync<ArgumentException>("destination", async () => await tokens.CopyTokenAsync(new char[4], default));
    }

    [Fact]
    public async Task TheNamespaceMountAndPathPrefix_AreUsed()
    {
        var vault = new FakeTransit { MountPath = "transit/team-a", PathPrefix = "/vault" };
        using var wrapper = new HashiCorpVaultTransitKeyWrapper(new Uri(FakeTransit.Address, "/vault/"), FakeTransit.KeyName, new FakeTokenSource(),
            options: new HashiCorpVaultTransitKeyWrapperOptions { HttpMessageHandler = vault, MountPath = "transit/team-a", Namespace = "team-a/prod" });

        await GenerateAsync(wrapper);

        Assert.Equal("team-a/prod", Assert.Single(vault.Requests).Namespace);
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Fact]
    public async Task Dispose_LeavesASuppliedHandlerUsable()
    {
        var vault = new FakeTransit();
        Create(vault).Dispose();

        using var again = Create(vault);
        await GenerateAsync(again);
    }

    [Theory]
    [InlineData("vault:v1:AAAA", true)]
    [InlineData("vault:v1234567890:AB+/=", true)]
    [InlineData("vault:v1:", false)]
    [InlineData("vault:v:AAAA", false)]
    [InlineData("vault:v1AAAA", false)]
    [InlineData("vault:v12345678901:AAAA", false)]
    [InlineData("vault:v1:AA-A", false)]
    [InlineData("vault:", false)]
    [InlineData("", false)]
    public void IsVaultCiphertext_AcceptsOnlyVaultsFormat(string value, bool expected)
        => Assert.Equal(expected, HashiCorpVaultTransitKeyWrapper.IsVaultCiphertext(Encoding.UTF8.GetBytes(value)));

    [Theory]
    [InlineData(0, 0, 200)]
    [InlineData(1, 0, 400)]
    [InlineData(2, 50, 850)]
    [InlineData(20, 0, 10_000)]
    [InlineData(20, 100, 10_100)]
    public void RetryDelay_DoublesUpToTheLimit_PlusJitter(int retry, int jitter, int expectedMilliseconds)
        => Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds),
            HashiCorpVaultTransitKeyWrapper.RetryDelay(TimeSpan.FromMilliseconds(200), retry, jitter));

    [Fact]
    public async Task ACryptoProvider_GeneratesAndRevealsItsDekThroughVault()
    {
        using var wrapper = Create(new FakeTransit(), context: null);
        await using var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(wrapper, expirySeconds: 60);

        var expected = "hello, vault"u8.ToArray();
        // Encrypt zeroes the plaintext it is given, so it gets a copy.
        var plaintext = expected.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var encryptedLength = provider.Encrypt(plaintext, encrypted);
        var decrypted = new byte[provider.GetDecryptedAllocationLength(encryptedLength)];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, encryptedLength), decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public async Task ReadKeyFile_ByDefault_RefusesAFileTheCurrentUserCouldHaveReplaced()
    {
        // The user's temp folder (Windows) or the shared /tmp (Linux, macOS): neither is somewhere
        // only administrators can write.
        using var wrapper = Create(new FakeTransit());
        var path = Path.Combine(Directory.CreateTempSubdirectory("hkdfguard-keys-").FullName, "v1.key");
        await File.WriteAllBytesAsync(path, "vault:v1:AAAA"u8.ToArray());
        try
        {
            if (!OperatingSystem.IsWindows() && Path.GetTempPath().StartsWith("/var/folders/", StringComparison.Ordinal))
                return; // macOS's per-user temp folder is private to its user; TrustedKeyFileTests covers macOS

            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await wrapper.ReadKeyFileAsync(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [WindowsFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ReadKeyFile_WithTheWritersAccountTrusted_ReadsTheFile_AndItReveals()
    {
        using var wrapper = Create(new FakeTransit(), keyFileTrust: WindowsTempDirectory.TrustCurrentUser);
        using var dir = new WindowsTempDirectory();

        var wrapped = await GenerateAsync(wrapper);
        var path = dir.Write("v1.key", wrapped);

        var read = await wrapper.ReadKeyFileAsync(path);
        Assert.Equal(wrapped, read);
        Assert.Equal(32, await wrapper.UnwrapAsync(read, new byte[32]));
    }

    [WindowsFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ReadKeyFile_TrustingEveryone_IsRefused()
    {
        using var wrapper = Create(new FakeTransit(), keyFileTrust: new KeyFileTrust { WindowsPrincipals = ["S-1-1-0"] });
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("v1.key", "vault:v1:AAAA"u8.ToArray());

        await Assert.ThrowsAsync<ArgumentException>(async () => await wrapper.ReadKeyFileAsync(path));
    }

    private sealed class LoggingHandler(HttpMessageHandler inner) : DelegatingHandler(inner);
}
