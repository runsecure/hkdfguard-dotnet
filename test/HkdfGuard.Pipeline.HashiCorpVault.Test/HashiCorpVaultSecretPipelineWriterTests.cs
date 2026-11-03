using System.Net;
using HkdfGuard.Abstractions;
using HkdfGuard.Integration.HashiCorpVault;
using HkdfGuard.Pipeline.HashiCorpVault.Test.TestHelpers;
using HkdfGuard.Pipeline.Test.TestHelpers;

namespace HkdfGuard.Pipeline.HashiCorpVault.Test;

/// <summary>The writer's contract, and what only it does, with its real HttpClient against a fake Vault.</summary>
public sealed class HashiCorpVaultSecretPipelineWriterTests : SecretPipelineWriterContractTests
{
    private readonly FakeVault _vault = new();
    private readonly StaticVaultTokenSource _token = new(FakeVault.Token);

    public override void Dispose()
    {
        _token.Dispose();
        base.Dispose();
    }

    // No key ring anywhere: the token is a plain source, and the only key is the protector's.
    protected override ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames)
        => Create(protector, secretNames);

    // A name without a key reads the default key, "value".
    protected override void SetText(string name, string text) => _vault.Set(name, text);

    protected override void SetKeys(string name, string json) => _vault.SetRawData(name, json);

    protected override void FailReads() => _vault.Answer = (HttpStatusCode.Forbidden, """{"errors":["permission denied"]}""");

    protected override Type ReadFailure => typeof(HttpRequestException);

    protected override IEnumerable<string> Reads => _vault.Reads;

    private HashiCorpVaultSecretPipelineWriter Create(IPipelineDataProtector protector, IList<string> secretNames, HashiCorpVaultPipelineOptions? options = null)
        => new(FakeVault.Address, _token, protector, secretNames, options ?? new HashiCorpVaultPipelineOptions { HttpMessageHandler = _vault, RetryDelay = TimeSpan.Zero });

    [Fact]
    public async Task EveryRead_SendsTheToken_AndTheResponseIsNeverBuffered()
    {
        _vault.SetData("myapp/db", new() { ["username"] = "app" });
        using var writer = Create(Protector, ["myapp/db#username"]);

        await writer.PullSecretsAsync();

        Assert.Equal("app", Decrypt(writer.ProtectedSecrets["myapp__db__username"], "myapp__db__username"));
        Assert.Equal([FakeVault.Token], _vault.Tokens);
        Assert.False(_vault.AnyResponseBuffered);
        Assert.Empty(_vault.UnexpectedRequests);
    }

    [Fact]
    public async Task ADeletedLatestVersion_OrABodyWithoutData_IsMissing()
    {
        _vault.SetDeleted("gone");
        using var writer = Create(Protector, ["gone"]);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());

        _vault.Answer = (HttpStatusCode.OK, """{"data":{"metadata":{"version":3}}}""");
        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());
        Assert.Contains("gone", ex.Message);
    }

    [Fact]
    public async Task TheDefaultKey_IsTheOptionsOne()
    {
        _vault.SetData("myapp/db", new() { ["password"] = "s3cret" });
        using var writer = Create(Protector, ["myapp/db"], new HashiCorpVaultPipelineOptions { HttpMessageHandler = _vault, DefaultKey = "password" });

        await writer.PullSecretsAsync();

        Assert.Equal("s3cret", Decrypt(writer.ProtectedSecrets["myapp__db"], "myapp__db"));
    }

    [Fact]
    public async Task KvVersion1_IsReadAtTheMountPath()
    {
        var vault = new FakeVault { KvVersion = VaultKvVersion.V1, MountPath = "kv" };
        vault.Set("item", "s3cret");
        using var writer = Create(Protector, ["item"], new HashiCorpVaultPipelineOptions { HttpMessageHandler = vault, KvVersion = VaultKvVersion.V1, MountPath = "kv" });

        await writer.PullSecretsAsync();

        Assert.Equal("s3cret", Decrypt(writer.ProtectedSecrets["item"], "item"));
        Assert.Empty(vault.UnexpectedRequests);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, """{"errors":["permission denied"]}""", ": permission denied")]
    [InlineData(HttpStatusCode.NotFound, """{"errors":["no handler for route \"secret/data/item\""]}""", ": no handler for route")]
    [InlineData(HttpStatusCode.NotFound, "<html>Not Found</html>", "")]
    [InlineData(HttpStatusCode.InternalServerError, "", "")]
    [InlineData(HttpStatusCode.BadGateway, "<html>Bad Gateway</html>", "")]
    public async Task AVaultError_Propagates_WithItsStatusAndErrors(HttpStatusCode status, string body, string detail)
    {
        _vault.Answer = (status, body);
        using var writer = Create(Protector, ["item"]);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => writer.PullSecretsAsync());

        Assert.Equal(status, ex.StatusCode);
        Assert.StartsWith($"Vault refused to read 'item': {(int)status} {status}{detail}", ex.Message);
    }

    [Theory]
    [InlineData("""[]""")]
    [InlineData("")]
    [InlineData("""{"data":""")]
    public async Task ASuccessThatIsntVaultsJson_IsRefused(string body)
    {
        _vault.Answer = (HttpStatusCode.OK, body);
        using var writer = Create(Protector, ["item"]);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Fact]
    public async Task ATokenSourceSupplyingNoToken_FailsThePull()
    {
        using var writer = new HashiCorpVaultSecretPipelineWriter(FakeVault.Address, new EmptyTokenSource(), Protector, ["item"],
            new HashiCorpVaultPipelineOptions { HttpMessageHandler = _vault });

        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.PullSecretsAsync());
        Assert.Empty(_vault.Reads);
    }

    [Fact]
    public async Task TheListIsCopied()
    {
        _vault.Set("item", "s3cret");
        var names = new List<string> { "item" };
        using var writer = Create(Protector, names);
        names.Add("other");

        await writer.PullSecretsAsync();

        Assert.Equal(["item"], writer.ProtectedSecrets.Keys);
    }

    [Theory]
    [InlineData("ConnectionStrings:Admin")]
    [InlineData("../escape")]
    [InlineData(".hidden")]
    public void ANameThatIsntAPath_IsRefused(string secretName)
        => Assert.Throws<ArgumentException>(() => Create(Protector, [secretName]));

    [Fact]
    public void APathLongerThanVaultReads_IsRefused()
    {
        Assert.True(HashiCorpVaultSecretPipelineWriter.IsValidSecretName(new string('a', HashiCorpVaultSecretPipelineWriter.MaxSecretNameLength)));
        Assert.False(HashiCorpVaultSecretPipelineWriter.IsValidSecretName(new string('a', HashiCorpVaultSecretPipelineWriter.MaxSecretNameLength + 1)));
    }

    [Fact]
    public void Constructor_ChecksTheAddressTokenSourceAndOptions()
    {
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretPipelineWriter(FakeVault.Address, null!, Protector, ["item"]));
        Assert.Throws<ArgumentException>(() => new HashiCorpVaultSecretPipelineWriter(new Uri("http://vault.example.com"), _token, Protector, ["item"]));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(Protector, ["item"], new HashiCorpVaultPipelineOptions { HttpMessageHandler = _vault, KvVersion = (VaultKvVersion)3 }));
        Assert.Throws<ArgumentException>(() => Create(Protector, ["item"], new HashiCorpVaultPipelineOptions { HttpMessageHandler = _vault, DefaultKey = "" }));
        Assert.Equal(VaultHttp.MaxRetryDelay, HashiCorpVaultPipelineOptions.MaxRetryDelay);

        using var defaults = new HashiCorpVaultSecretPipelineWriter(FakeVault.Address, _token, Protector, ["item"]);
    }

    private sealed class EmptyTokenSource : IVaultTokenSource
    {
        public ValueTask<int> CopyTokenAsync(Memory<char> destination, CancellationToken cancellationToken) => ValueTask.FromResult(0);
    }
}
