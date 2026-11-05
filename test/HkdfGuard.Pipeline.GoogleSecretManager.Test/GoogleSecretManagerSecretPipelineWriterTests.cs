using System.Security.Cryptography;
using Google.Apis.Auth.OAuth2;
using Google.Cloud.SecretManager.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using HkdfGuard.Abstractions;
using HkdfGuard.Pipeline.GoogleSecretManager.Test.TestHelpers;
using HkdfGuard.Pipeline.Test.TestHelpers;

namespace HkdfGuard.Pipeline.GoogleSecretManager.Test;

/// <summary>The writer's contract, and what only it does, with its real gax client and interceptor against a fake call invoker.</summary>
public sealed class GoogleSecretManagerSecretPipelineWriterTests : SecretPipelineWriterContractTests
{
    private readonly FakeSecretManager _google = new();

    // No key ring anywhere: the only key is the protector's.
    protected override ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames)
        => Create(protector, secretNames);

    protected override void SetText(string name, string text) => _google.Set(name, text);

    protected override void SetKeys(string name, string json) => _google.Set(name, json);

    protected override void FailReads() => _google.Failure = new RpcException(new Status(StatusCode.PermissionDenied, "Denied in a test."));

    protected override Type ReadFailure => typeof(RpcException);

    protected override IEnumerable<string> Reads => _google.Gets;

    private GoogleSecretManagerSecretPipelineWriter Create(IPipelineDataProtector protector, IList<string> secretNames)
        => new(_google, FakeSecretManager.ProjectId, protector, secretNames);

    [Fact]
    public async Task EachSecretsLatestVersion_IsReadAsynchronously()
    {
        _google.Set("api-key", "value");
        using var writer = Create(Protector, ["api-key"]);

        await writer.PullSecretsAsync();

        Assert.Equal(["projects/hkdfguard-test/secrets/api-key/versions/latest"], _google.Accesses);
        Assert.Equal(1, _google.AsyncCalls);
        Assert.Empty(_google.UnexpectedCalls);
    }

    [Fact]
    public async Task ANameWithoutAKey_ReadsTheWholePayload()
    {
        _google.Set("db_login", """{"user":"app"}""");
        using var writer = Create(Protector, ["db_login", "db_login#user"]);

        await writer.PullSecretsAsync();

        Assert.Equal("""{"user":"app"}""", Decrypt(writer.ProtectedSecrets["db_login"], "db_login"));
        Assert.Equal("app", Decrypt(writer.ProtectedSecrets["db_login__user"], "db_login__user"));
    }

    [Fact]
    public async Task TheDeserializedPayload_AndGrpcsReceiveBuffer_AreZeroed()
    {
        _google.Set("item", "s3cret");
        using var writer = Create(Protector, ["item"]);

        await writer.PullSecretsAsync();

        Assert.All(Assert.Single(_google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
        Assert.All(Assert.Single(_google.ReceiveBuffers), b => Assert.Equal(0, b));
    }

    [Fact]
    public void TheScrubber_ZeroesASynchronousCallsReceiveBufferToo()
    {
        _google.Set("item", "s3cret");
        var client = new SecretManagerServiceClientBuilder { CallInvoker = _google.Intercept(new ReceiveBufferScrubber()) }.Build();

        var response = client.AccessSecretVersion(new SecretVersionName(FakeSecretManager.ProjectId, "item", "latest"));

        Assert.Equal("s3cret", response.Payload.Data.ToStringUtf8());
        Assert.All(Assert.Single(_google.ReceiveBuffers), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task APayloadThatIsntUtf8Text_IsRefused_AndZeroed()
    {
        _google.Set("binary", [0xFF, 0xFE, 0x00, 0x80]);
        using var writer = Create(Protector, ["binary"]);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());

        Assert.Empty(writer.ProtectedSecrets);
        Assert.All(Assert.Single(_google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task APayloadNotMatchingItsChecksum_IsRefused_AndZeroed()
    {
        _google.Set("item", "s3cret");
        _google.Tamper = r => r.Payload.DataCrc32C += 1;
        using var writer = Create(Protector, ["item"]);

        await Assert.ThrowsAsync<CryptographicException>(() => writer.PullSecretsAsync());

        Assert.Empty(writer.ProtectedSecrets);
        Assert.All(Assert.Single(_google.Payloads).ToByteArray(), b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData("projects/123456789012/secrets/other/versions/1")]
    [InlineData("not a resource name")]
    public async Task AResponseForAnotherSecret_IsRefused(string name)
    {
        _google.Set("item", "s3cret");
        _google.Tamper = r => r.Name = name;
        using var writer = Create(Protector, ["item"]);

        await Assert.ThrowsAsync<CryptographicException>(() => writer.PullSecretsAsync());
    }

    [Fact]
    public async Task AResponseWithoutAPayload_HoldsNothing_AndOneWithoutAChecksum_IsAccepted()
    {
        _google.Set("none", "x");
        _google.Set("unchecked", "s3cret");
        _google.Tamper = r =>
        {
            if (r.Name.Contains("/none/"))
                r.Payload = null;
            else
                r.Payload.ClearDataCrc32C();
        };
        using var writer = Create(Protector, ["none", "unchecked"]);

        await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());

        Assert.Equal("s3cret", Decrypt(writer.ProtectedSecrets["unchecked"], "unchecked"));
    }

    [Fact]
    public void Create_MakesAndDisposesItsOwnChannel()
    {
        var credential = GoogleCredential.FromAccessToken("ya29.a-test-token");
        var writer = GoogleSecretManagerSecretPipelineWriter.Create(FakeSecretManager.ProjectId, credential, Protector, ["item"]);
        writer.Dispose();

        Assert.Throws<ArgumentNullException>(() => GoogleSecretManagerSecretPipelineWriter.Create(FakeSecretManager.ProjectId, null!, Protector, ["item"]));
        Assert.Throws<ArgumentException>(() => GoogleSecretManagerSecretPipelineWriter.Create("bad/project", credential, Protector, ["item"]));
    }

    [Theory]
    [InlineData("prod/app")]
    [InlineData("db.login")]
    public void AnIdSecretManagerCantHold_IsRefused(string secretName)
        => Assert.Throws<ArgumentException>(() => Create(Protector, [secretName]));

    [Fact]
    public void IsValidSecretName_IsSecretManagersRule()
    {
        Assert.True(GoogleSecretManagerSecretPipelineWriter.IsValidSecretName("db_login-2"));
        Assert.True(GoogleSecretManagerSecretPipelineWriter.IsValidSecretName(new string('a', GoogleSecretManagerSecretPipelineWriter.MaxSecretNameLength)));
        Assert.False(GoogleSecretManagerSecretPipelineWriter.IsValidSecretName(new string('a', GoogleSecretManagerSecretPipelineWriter.MaxSecretNameLength + 1)));
        Assert.False(GoogleSecretManagerSecretPipelineWriter.IsValidSecretName(""));
        Assert.False(GoogleSecretManagerSecretPipelineWriter.IsValidSecretName(null));
    }

    [Fact]
    public void Constructor_ChecksTheCallInvokerAndProject()
    {
        Assert.Throws<ArgumentNullException>(() => new GoogleSecretManagerSecretPipelineWriter(null!, FakeSecretManager.ProjectId, Protector, ["item"]));
        Assert.Throws<ArgumentNullException>(() => new GoogleSecretManagerSecretPipelineWriter(_google, null!, Protector, ["item"]));
        Assert.Throws<ArgumentException>(() => new GoogleSecretManagerSecretPipelineWriter(_google, "", Protector, ["item"]));
        Assert.Throws<ArgumentException>(() => new GoogleSecretManagerSecretPipelineWriter(_google, "projects/x", Protector, ["item"]));
    }

    [Fact]
    public void Crc32C_IsCastagnolis()
        => Assert.Equal(0xE3069283L, GoogleSecretManagerSecretPipelineWriter.Crc32C("123456789"u8));
}
