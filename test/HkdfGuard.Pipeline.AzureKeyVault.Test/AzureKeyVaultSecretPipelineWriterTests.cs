using System.Net;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Abstractions;
using HkdfGuard.Pipeline.AzureKeyVault.Test.TestHelpers;
using HkdfGuard.Pipeline.Test.TestHelpers;

namespace HkdfGuard.Pipeline.AzureKeyVault.Test;

/// <summary>The writer's contract, and what only it does, with a real SecretClient and its own pipeline policy against a fake Key Vault.</summary>
public sealed class AzureKeyVaultSecretPipelineWriterTests : SecretPipelineWriterContractTests
{
    private readonly FakeKeyVault _vault = new();

    // No key ring anywhere: the only key is the protector's.
    protected override ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames)
        => Create(protector, secretNames);

    protected override void SetText(string name, string text) => _vault.Set(name, text);

    protected override void SetKeys(string name, string json) => _vault.Set(name, json);

    protected override void FailReads() => _vault.FailWith = HttpStatusCode.Forbidden;

    protected override Type ReadFailure => typeof(RequestFailedException);

    protected override IEnumerable<string> Reads => _vault.Gets;

    private AzureKeyVaultSecretPipelineWriter Create(IPipelineDataProtector protector, IList<string> secretNames, SecretClientOptions? options = null)
        => new(FakeKeyVault.VaultUri, new FakeCredential(), protector, secretNames, options ?? _vault.Options());

    [Fact]
    public async Task SecretClient_SeesOnlyAnEmptyObject()
    {
        _vault.Set("Item", "s3cret");
        using var writer = Create(Protector, ["Item"]);

        await writer.PullSecretsAsync();

        Assert.Equal(["{}"], _vault.BodiesSeenBySecretClient);
        Assert.Empty(_vault.UnexpectedRequests);
    }

    [Fact]
    public async Task AnotherClientOnTheSameOptions_ReadsSecretsAsUsual()
    {
        _vault.Set("Item", "s3cret");
        var options = _vault.Options();
        using var writer = Create(Protector, ["Item"], options);
        var other = new SecretClient(FakeKeyVault.VaultUri, new FakeCredential(), options);

        Assert.Equal("s3cret", (await other.GetSecretAsync("Item")).Value.Value);
        Assert.Equal("s3cret", other.GetSecret("Item").Value.Value);
    }

    [Fact]
    public async Task ANameWithoutAKey_ReadsTheWholeValue()
    {
        _vault.Set("Db-Login", """{"user":"app"}""");
        using var writer = Create(Protector, ["Db-Login", "Db-Login#user"]);

        await writer.PullSecretsAsync();

        Assert.Equal("""{"user":"app"}""", Decrypt(writer.ProtectedSecrets["Db-Login"], "Db-Login"));
        Assert.Equal("app", Decrypt(writer.ProtectedSecrets["Db-Login__user"], "Db-Login__user"));
        Assert.Equal(["Db-Login"], _vault.Gets);
    }

    [Theory]
    [InlineData("""{"value":"x" """)]
    [InlineData("""["value"]""")]
    [InlineData("")]
    public async Task AResponseThatIsntKeyVaultsJson_IsRefused(string body)
    {
        _vault.RawBody = body;
        using var writer = Create(Protector, ["Item"]);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Fact]
    public async Task AResponseWithoutAStringValue_HoldsNothing()
    {
        _vault.RawBody = """{"value":5,"id":"x"}""";
        using var writer = Create(Protector, ["Item"]);

        await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());
    }

    [Fact]
    public async Task AResponseWithoutAContentStream_IsLeftToSecretClient()
    {
        _vault.Set("Item", "s3cret");
        var options = _vault.Options();
        options.AddPolicy(new DropContent(), HttpPipelinePosition.BeforeTransport);
        using var writer = Create(Protector, ["Item"], options);

        // Nothing to capture, so the policy passes it on, and SecretClient refuses a 200 without a body.
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => writer.PullSecretsAsync());
        Assert.Equal("utf8Json", ex.ParamName);
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Fact]
    public void TheSynchronousPipeline_IsRefusedInsideAScope()
    {
        var options = _vault.Options();
        options.AddPolicy(PipelineSecretCapturePolicy.Instance, HttpPipelinePosition.PerRetry);
        var client = new SecretClient(FakeKeyVault.VaultUri, new FakeCredential(), options);
        _vault.Set("Item", "s3cret");

        using (PipelineSecretCapturePolicy.Scope(_ => { }))
            Assert.Throws<NotSupportedException>(() => client.GetSecret("Item"));
    }

    [Theory]
    [InlineData("Db_Password")]
    [InlineData("prod/app")]
    public void ANameKeyVaultCantHold_IsRefused(string secretName)
        => Assert.Throws<ArgumentException>(() => Create(Protector, [secretName]));

    [Fact]
    public void IsValidSecretName_IsKeyVaultsRule()
    {
        Assert.True(AzureKeyVaultSecretPipelineWriter.IsValidSecretName("Db-Login-2"));
        Assert.True(AzureKeyVaultSecretPipelineWriter.IsValidSecretName(new string('a', AzureKeyVaultSecretPipelineWriter.MaxSecretNameLength)));
        Assert.False(AzureKeyVaultSecretPipelineWriter.IsValidSecretName(new string('a', AzureKeyVaultSecretPipelineWriter.MaxSecretNameLength + 1)));
        Assert.False(AzureKeyVaultSecretPipelineWriter.IsValidSecretName(""));
        Assert.False(AzureKeyVaultSecretPipelineWriter.IsValidSecretName(null));
    }

    [Fact]
    public void Constructor_ChecksTheVaultCredentialAndOptions()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretPipelineWriter(null!, new FakeCredential(), Protector, ["Item"]));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretPipelineWriter(FakeKeyVault.VaultUri, null!, Protector, ["Item"]));

        var logging = new SecretClientOptions();
        logging.Diagnostics.IsLoggingContentEnabled = true;
        Assert.Throws<ArgumentException>(() => Create(Protector, ["Item"], logging));

        using var defaults = new AzureKeyVaultSecretPipelineWriter(FakeKeyVault.VaultUri, new FakeCredential(), Protector, ["Item"]);
    }

    // Nearest the transport, so the writer's policy sees a 200 with no body.
    private sealed class DropContent : HttpPipelineSynchronousPolicy
    {
        public override void OnReceivedResponse(HttpMessage message)
        {
            if (message.Response.Status == 200)
                message.Response.ContentStream = null;
        }
    }
}
