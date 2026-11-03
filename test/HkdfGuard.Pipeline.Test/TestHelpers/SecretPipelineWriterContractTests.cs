using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.Pipeline.Test.TestHelpers;

/// <summary>
/// What every <see cref="ISecretPipelineWriter"/> must do, whatever its store: run against each
/// store's writer and fake by a test class deriving from this one, so every writer meets every
/// scenario. Secret names here are lower-case letters, digits and hyphens, which every store
/// accepts; a store's own tests cover what only it does.
/// </summary>
public abstract class SecretPipelineWriterContractTests : IDisposable
{
    protected SecretPipelineWriterContractTests()
    {
        Protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
        Folder = Path.Join(Path.GetTempPath(), "hkdfguard-pipeline-" + Guid.NewGuid().ToString("N"));
    }

    /// <summary>The only key in the pipeline: no key ring anywhere.</summary>
    protected AesGcmPipelineDataProtector Protector { get; }

    /// <summary>A folder to write to, which doesn't exist until a test makes it.</summary>
    protected string Folder { get; }

    /// <summary>The store's writer, reading from this test's fake.</summary>
    protected abstract ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames);

    /// <summary>Stores text as the value a name without a key reads.</summary>
    protected abstract void SetText(string name, string text);

    /// <summary>Stores a secret whose keys are the members of json, a JSON object - which may hold a member twice.</summary>
    protected abstract void SetKeys(string name, string json);

    /// <summary>Makes every later read fail as the store fails, with <see cref="ReadFailure"/>.</summary>
    protected abstract void FailReads();

    /// <summary>The exception a failing read throws.</summary>
    protected abstract Type ReadFailure { get; }

    /// <summary>The name of every secret the store was asked for, in order.</summary>
    protected abstract IEnumerable<string> Reads { get; }

    protected ISecretPipelineWriter CreateWriter(params string[] secretNames) => CreateWriter(Protector, secretNames);

    protected string Decrypt(string encrypted, string fileName)
    {
        var result = new char[Protector.GetMaxDecryptedLength(encrypted)];
        return new string(result, 0, Protector.Decrypt(encrypted, fileName, result));
    }

    public virtual void Dispose()
    {
        Protector.Dispose();
        if (Directory.Exists(Folder))
            Directory.Delete(Folder, recursive: true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Pull_ReadsEachSecretOnce_AndKeepsEveryValueEncryptedForItsFileName()
    {
        SetKeys("db-login", """{"username":"app","password":"s3cr\"et","port":5432,"tls":true,"off":false,"unasked":"x"}""");
        SetText("api-key", "api-key-value");
        using var writer = CreateWriter("db-login#username", "db-login#password", "db-login#port", "db-login#tls", "db-login#off", "api-key");

        await writer.PullSecretsAsync();

        var secrets = writer.ProtectedSecrets;
        Assert.Equal(6, secrets.Count);
        Assert.StartsWith("enc::v3::", secrets["db-login__password"]);
        Assert.Equal("app", Decrypt(secrets["db-login__username"], "db-login__username"));
        Assert.Equal("s3cr\"et", Decrypt(secrets["db-login__password"], "db-login__password"));
        Assert.Equal("5432", Decrypt(secrets["db-login__port"], "db-login__port"));
        Assert.Equal("true", Decrypt(secrets["db-login__tls"], "db-login__tls"));
        Assert.Equal("false", Decrypt(secrets["db-login__off"], "db-login__off"));
        Assert.Equal("api-key-value", Decrypt(secrets["api-key"], "api-key"));
        Assert.Equal(["db-login", "api-key"], Reads);
    }

    [Fact]
    public async Task AValue_IsBoundToItsFileName()
    {
        SetText("item", "s3cret");
        using var writer = CreateWriter("item");
        await writer.PullSecretsAsync();

        Assert.ThrowsAny<CryptographicException>(() => Decrypt(writer.ProtectedSecrets["item"], "other"));
    }

    [Fact]
    public async Task ALargeValue_IsProtected()
    {
        var large = new string('x', ArrayUtility.MaxStackChars + 1);
        SetText("big", large);
        using var writer = CreateWriter("big");

        await writer.PullSecretsAsync();

        Assert.Equal(large, Decrypt(writer.ProtectedSecrets["big"], "big"));
    }

    [Fact]
    public async Task APullAgain_ReplacesWhatTheLastKept()
    {
        SetText("item", "first");
        using var writer = CreateWriter("item");
        await writer.PullSecretsAsync();
        SetText("item", "second");

        await writer.PullSecretsAsync();

        Assert.Equal("second", Decrypt(writer.ProtectedSecrets["item"], "item"));
    }

    [Fact]
    public async Task MissingValues_AreAllReported_AndTheRestKept()
    {
        SetKeys("db-login", """{"username":"app","empty":"","nothing":null,"nested":{"a":"b"},"list":[1]}""");
        SetText("plain", "not json");
        SetText("trailing", """{"key":"v"} more""");
        SetText("array", """["key"]""");
        SetText("blank", "");
        using var writer = CreateWriter("absent", "db-login#username", "db-login#password", "db-login#empty", "db-login#nothing",
            "db-login#nested", "db-login#list", "plain#key", "trailing#key", "array#key", "blank");

        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());

        Assert.Equal("The secret store holds no value for: absent, db-login#password, db-login#empty, db-login#nothing, "
            + "db-login#nested, db-login#list, plain#key, trailing#key, array#key, blank.", ex.Message);
        Assert.Equal(["db-login__username"], writer.ProtectedSecrets.Keys);

        // What was found is still written.
        writer.WriteProtectedSecretFiles(Folder);
        Assert.Equal(["db-login__username"], Directory.GetFiles(Folder).Select(Path.GetFileName));
    }

    [Fact]
    public async Task ASecretHoldingAKeyTwice_IsRefused()
    {
        SetKeys("db-login", """{"password":"a","password":"b"}""");
        using var writer = CreateWriter("db-login#password");

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Fact]
    public async Task AFailedRead_Propagates_AndKeepsNothing()
    {
        SetText("item", "s3cret");
        using var writer = CreateWriter("item");
        await writer.PullSecretsAsync();
        FailReads();

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => writer.PullSecretsAsync());

        Assert.IsAssignableFrom(ReadFailure, ex);
        Assert.Empty(writer.ProtectedSecrets);
        Assert.Throws<InvalidOperationException>(() => writer.WriteProtectedSecretFiles(Folder));
    }

    [Fact]
    public async Task ThroughTheInterface_WritesOneFilePerSecret_AsUtf8WithoutABom()
    {
        SetKeys("db-login", """{"password":"pässwörd"}""");
        SetText("api-key", "key");
        using var writer = CreateWriter("db-login#password", "api-key");
        await writer.PullSecretsAsync();

        writer.WriteProtectedSecretFiles(Folder);

        Assert.Equal(["api-key", "db-login__password"], Directory.GetFiles(Folder).Select(Path.GetFileName).Order());
        var bytes = await File.ReadAllBytesAsync(Path.Join(Folder, "db-login__password"));
        Assert.NotEqual(0xEF, bytes[0]);
        Assert.Equal("pässwörd", Decrypt(Encoding.UTF8.GetString(bytes), "db-login__password"));
    }

    [Fact]
    public async Task WriteProtectedSecretFiles_ReplacesOnlyItsOwnFiles()
    {
        Directory.CreateDirectory(Folder);
        await File.WriteAllTextAsync(Path.Join(Folder, "item"), "old");
        await File.WriteAllTextAsync(Path.Join(Folder, "unrelated"), "untouched");
        SetText("item", "new");
        using var writer = CreateWriter("item");
        await writer.PullSecretsAsync();

        writer.WriteProtectedSecretFiles(Folder);

        Assert.Equal("new", Decrypt(await File.ReadAllTextAsync(Path.Join(Folder, "item")), "item"));
        Assert.Equal("untouched", await File.ReadAllTextAsync(Path.Join(Folder, "unrelated")));
    }

    [Fact]
    public void WriteProtectedSecretFiles_BeforeAPull_OrWithoutAFolder_Throws()
    {
        using var writer = CreateWriter("item");

        Assert.Throws<InvalidOperationException>(() => writer.WriteProtectedSecretFiles(Folder));
        Assert.Throws<ArgumentNullException>(() => writer.WriteProtectedSecretFiles(null!));
        Assert.Throws<ArgumentException>(() => writer.WriteProtectedSecretFiles(""));
        Assert.False(Directory.Exists(Folder));
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad name")]
    [InlineData("#key")]
    [InlineData("db-login#")]
    [InlineData("db-login#bad key")]
    [InlineData("db-login#a:b")]
    public void AnInvalidName_IsRefused(string secretName)
        => Assert.Throws<ArgumentException>(() => CreateWriter(secretName));

    [Fact]
    public void Constructor_ChecksTheListAndTheProtector()
    {
        Assert.Throws<ArgumentNullException>(() => CreateWriter(null!, ["item"]));
        Assert.Throws<ArgumentNullException>(() => CreateWriter(Protector, null!));
        Assert.Throws<ArgumentException>(() => CreateWriter(Protector, []));
        Assert.Throws<ArgumentException>(() => CreateWriter(Protector, [null!]));
        Assert.Throws<ArgumentException>(() => CreateWriter(Protector, ["item", "ITEM"]));
        Assert.Throws<ArgumentException>(() => CreateWriter(Protector, ["item", "item"]));
    }
}
