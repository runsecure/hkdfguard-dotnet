using System.Net;
using System.Text;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// What the client refuses so a request can't be changed beyond what its caller wrote: header values
/// that would start another header, paths that System.Uri would send elsewhere, and responses larger
/// than it will hold.
/// </summary>
public class VaultClientHardeningTests
{
    private static Dictionary<string, IReadOnlyList<string>> Header(string name, string value) => new() { [name] = [value] };

    [Theory]
    [InlineData("abc\r\nX-Vault-Namespace: admin")]
    [InlineData("abc\nX-Vault-Token: hvs.other")]
    [InlineData("abc\rdef")]
    [InlineData("nul\0")]
    [InlineData("bell\u0007")]
    [InlineData("del\u007F")]
    [InlineData("café")]
    public async Task CustomHeaderValues_ThatAreNotPrintableAsciiSpaceOrTab_AreRefused_AndNothingIsSent(string value)
    {
        using var t = await TestClient.CreateAsync();
        var headers = Header("x-trace-id", value);

        var ex = Assert.Throws<ArgumentException>(() => t.Client.SetCustomHeaders(headers));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ReadAsync("a", new VaultRequestOptions { CustomHeaders = headers }));

        // The value may be a credential: never quoted.
        Assert.DoesNotContain(value, ex.Message, StringComparison.Ordinal);
        Assert.Empty(t.Vault.Requests);
    }

    [Theory]
    [InlineData("x-trace id")]
    [InlineData("x-trace:id")]
    [InlineData("x-trace\r\nX-Vault-Token")]
    [InlineData("")]
    [InlineData("café")]
    public async Task CustomHeaderNames_ThatAreNotTokens_AreRefused(string name)
    {
        using var t = await TestClient.CreateAsync();

        Assert.Throws<ArgumentException>(() => t.Client.SetCustomHeaders(Header(name, "v")));
        Assert.Empty(t.Vault.Requests);
    }

    [Fact]
    public async Task CustomHeaders_WithANullValueOrNoValueList_AreRefused()
    {
        using var t = await TestClient.CreateAsync();

        Assert.Throws<ArgumentException>(() => t.Client.SetCustomHeaders(new Dictionary<string, IReadOnlyList<string>> { ["x-a"] = [null!] }));
        Assert.Throws<ArgumentException>(() => t.Client.SetCustomHeaders(new Dictionary<string, IReadOnlyList<string>> { ["x-a"] = null! }));
    }

    [Fact]
    public async Task CustomHeaderValues_WithSpacesTabsAndPunctuation_AreSentAsTheyAre()
    {
        using var t = await TestClient.CreateAsync();
        const string value = "Bearer a.b-c_d~e!f \t\"quoted\" (x) [y] {z} <w>";

        await t.Client.ReadAsync("a", new VaultRequestOptions { CustomHeaders = Header("x-trace-id", value) });

        Assert.Equal(value, t.Vault.Single().Header("x-trace-id"));
        Assert.Null(t.Vault.Single().Header("X-Vault-Namespace"));
    }

    [Theory]
    [InlineData("secret/data/../../sys/policies/acl/root")]
    [InlineData("secret/data/..")]
    [InlineData("secret/./data")]
    [InlineData("..")]
    [InlineData("secret/data/foo?list=true")]
    [InlineData("secret/data/foo#bar")]
    [InlineData("secret/data/%2e%2e/sys")]
    [InlineData("secret/data/foo%3Flist=true")]
    [InlineData("secret\\..\\sys")]
    [InlineData("secret//data")]
    [InlineData("secret/data/foo\r\n")]
    [InlineData("secret/data/foo\0")]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("//")]
    public async Task GenericMethods_RefuseAPathThatUriWouldSendElsewhere_AndSendNothing(string path)
    {
        using var t = await TestClient.CreateAsync();

        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ReadAsync(path));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ReadRawAsync(path));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.WriteAsync(path, new Dictionary<string, object?>()));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.WriteFromBytesAsync(path, "{}"u8.ToArray()));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.WriteFromStreamAsync(path, new MemoryStream("{}"u8.ToArray())));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.ListAsync(path));
        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.DeleteAsync(path));

        Assert.Empty(t.Vault.Requests);
    }

    [Theory]
    [InlineData("secret/data/foo", "/v1/secret/data/foo")]
    [InlineData("/secret/data/foo", "/v1/secret/data/foo")]
    [InlineData("v1/secret/data/foo", "/v1/secret/data/foo")]
    [InlineData("/v1/secret/data/foo", "/v1/secret/data/foo")]
    [InlineData("secret/metadata/", "/v1/secret/metadata/")]
    [InlineData("secret/data/my app", "/v1/secret/data/my%20app")]
    [InlineData("secret/data/a..b/.hidden/x.", "/v1/secret/data/a..b/.hidden/x.")]
    [InlineData("secret/data/user@example.com", "/v1/secret/data/user@example.com")]
    public async Task GenericMethods_SendAnOrdinaryPath_ToExactlyThatPath(string path, string expected)
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.ReadAsync(path);

        Assert.Equal(expected, t.Vault.Single().Uri.AbsolutePath);
        Assert.Equal("", t.Vault.Single().Uri.Query);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    public async Task TypedMethods_RefuseADotSegmentParameter(string name)
    {
        using var t = await TestClient.CreateAsync();

        await Assert.ThrowsAsync<ArgumentException>(() => t.Client.Secrets.KvV2ReadAsync(name));
        Assert.Empty(t.Vault.Requests);
    }

    [Theory]
    [InlineData("...", "/v1/kv-v2/data/...")]
    [InlineData("../x", "/v1/kv-v2/data/..%2Fx")]
    public async Task TypedMethods_KeepAnyOtherParameterInOneSegment(string name, string expected)
    {
        using var t = await TestClient.CreateAsync();

        await t.Client.Secrets.KvV2ReadAsync(name);

        Assert.Equal(expected, t.Vault.Single().Uri.AbsolutePath);
    }

    [Fact]
    public async Task MaxResponseBytes_DefaultsTo16MiB_AndMustBePositive()
    {
        Assert.Equal(16 * 1024 * 1024, new VaultClientOptions().MaxResponseBytes);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => TestClient.CreateAsync(o => o.MaxResponseBytes = 0));
    }

    [Fact]
    public async Task AResponseDeclaringMoreThanTheLimit_IsRefusedBeforeItIsRead()
    {
        var body = new CountingStream(endless: false, length: 2048);
        using var t = await TestClient.CreateAsync(o => o.MaxResponseBytes = 1024);
        t.Vault.Then(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) { Headers = { ContentLength = 2048 } } });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => t.Client.ReadAsync("secret/foo"));

        Assert.Contains("MaxResponseBytes", ex.Message);
        Assert.Equal(0, body.BytesRead);
    }

    [Fact]
    public async Task AnEndlessResponseWithoutALength_IsCutOffJustPastTheLimit()
    {
        var body = new CountingStream(endless: true);
        using var t = await TestClient.CreateAsync(o => o.MaxResponseBytes = 1024);
        t.Vault.Then(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => t.Client.ReadAsync("secret/foo"));

        Assert.Contains("MaxResponseBytes", ex.Message);
        Assert.Equal(1025, body.BytesRead);
    }

    [Fact]
    public async Task AResponseOfExactlyTheLimit_IsRead()
    {
        var json = """{"data":{"k":"v"}}""";
        using var t = await TestClient.CreateAsync(o => o.MaxResponseBytes = Encoding.UTF8.GetByteCount(json));
        t.Vault.Then(HttpStatusCode.OK, json);

        var response = await t.Client.ReadAsync("secret/foo");

        Assert.Equal("v", response!.Data!["k"].GetString());
    }

    [Fact]
    public async Task AnErrorBodyThatIsNotVaults_IsQuotedOnlyInPart_ButKeptWhole()
    {
        var page = "<html>" + new string('x', 5000) + "</html>";
        using var t = await TestClient.CreateAsync();
        t.Vault.Then(_ => new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(page) });

        var ex = await Assert.ThrowsAsync<VaultResponseException>(() => t.Client.ReadAsync("secret/foo"));

        Assert.True(ex.Message.Length < 1200, $"message is {ex.Message.Length} chars");
        Assert.Contains($"({Encoding.UTF8.GetByteCount(page)} bytes in all)", ex.Message);
        Assert.Equal(page, Encoding.UTF8.GetString(ex.RawResponseBytes!));
    }

    [Fact]
    public async Task ReadErrorsAsync_ReadsVaultsErrorList_AndGivesUpOnABodyOverTheBound()
    {
        Assert.Equal(["denied"], await VaultHttp.ReadErrorsAsync(new MemoryStream("""{"errors":["denied"]}"""u8.ToArray()), default));

        var endless = new CountingStream(endless: true);
        Assert.Null(await VaultHttp.ReadErrorsAsync(endless, default));
        Assert.Equal(VaultHttp.MaxErrorBodyBytes + 1, endless.BytesRead);
    }

    /// <summary>A non-seekable stream of '{' bytes, endless or of a fixed length, counting what is read.</summary>
    private sealed class CountingStream(bool endless, long length = 0) : Stream
    {
        public long BytesRead { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var n = endless ? buffer.Length : (int)Math.Min(buffer.Length, length - BytesRead);
            buffer[..n].Fill((byte)'{');
            BytesRead += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Read(buffer.Span));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.FromResult(Read(buffer.AsSpan(offset, count)));

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
