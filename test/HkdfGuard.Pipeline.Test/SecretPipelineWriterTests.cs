using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Pipeline.Test.TestHelpers;

namespace HkdfGuard.Pipeline.Test;

// A store of secret values by name, as UTF-8 bytes; names are ASCII letters, digits, hyphens and '/'.
internal sealed class FakeWriter(IPipelineDataProtector protector, IList<string> secretNames, FakeStore store, string? defaultKey = null)
    : SecretPipelineWriter(protector, secretNames, FakeStore.IsValidName, defaultKey)
{
    public bool Disposed { get; private set; }

    protected override Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        store.Reads.Add(name);
        if (store.FailWith is not null)
            throw store.FailWith;
        if (store.Secrets.TryGetValue(name, out var secret))
            ProtectSecret(secret, requests, values);
        return Task.CompletedTask;
    }

    protected override void Dispose(bool disposing)
    {
        Disposed = disposing;
        base.Dispose(disposing);
    }
}

internal sealed class FakeStore
{
    public Dictionary<string, byte[]> Secrets { get; } = new(StringComparer.Ordinal);

    public List<string> Reads { get; } = [];

    public Exception? FailWith { get; set; }

    public static bool IsValidName(string name) => name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '/');

    public void Set(string name, string value) => Secrets[name] = Encoding.UTF8.GetBytes(value);
}

/// <summary>The shared writer's contract over an in-memory store, and what only it does: the default key, file names, its own arguments.</summary>
public sealed class SecretPipelineWriterTests : SecretPipelineWriterContractTests
{
    private readonly FakeStore _store = new();

    protected override ISecretPipelineWriter CreateWriter(IPipelineDataProtector protector, IList<string> secretNames)
        => new FakeWriter(protector, secretNames, _store);

    protected override void SetText(string name, string text) => _store.Set(name, text);

    protected override void SetKeys(string name, string json) => _store.Set(name, json);

    protected override void FailReads() => _store.FailWith = new HttpRequestException("down");

    protected override Type ReadFailure => typeof(HttpRequestException);

    [Fact]
    public async Task WritingAgain_ReplacesEachFile_AndLeavesNoTemporaryFileBehind()
    {
        SetText("api-key", "first");
        using var writer = CreateWriter("api-key");
        await writer.PullSecretsAsync();
        writer.WriteProtectedSecretFiles(Folder);
        writer.WriteJsonSecrets(Path.Join(Folder, "secrets.json"));
        var first = await File.ReadAllTextAsync(Path.Join(Folder, "api-key"));

        SetText("api-key", "second");
        await writer.PullSecretsAsync();
        writer.WriteProtectedSecretFiles(Folder);
        writer.WriteJsonSecrets(Path.Join(Folder, "secrets.json"));

        Assert.Equal(["api-key", "secrets.json"], Directory.GetFiles(Folder).Select(Path.GetFileName).Order());
        Assert.NotEqual(first, await File.ReadAllTextAsync(Path.Join(Folder, "api-key")));
        Assert.Equal("second", Decrypt(await File.ReadAllTextAsync(Path.Join(Folder, "api-key")), "api-key"));
    }

    [Fact]
    public void AWriteThatFails_LeavesTheOldFileIntact_AndRemovesItsTemporaryFile()
    {
        Directory.CreateDirectory(Folder);
        var path = Path.Join(Folder, "api-key");
        File.WriteAllText(path, "old");

        Assert.Throws<IOException>(() => SecretPipelineWriter.ReplaceFile(path, stream =>
        {
            stream.Write("partial"u8);
            throw new IOException("disk full");
        }));

        Assert.Equal("old", File.ReadAllText(path));
        Assert.Equal(["api-key"], Directory.GetFiles(Folder).Select(Path.GetFileName));
    }

    [Fact]
    public async Task ASymbolicLinkAtAFilesName_IsReplaced_NotWrittenThrough()
    {
        Directory.CreateDirectory(Folder);
        var outside = Path.Join(Folder, "..", $"outside-{Guid.NewGuid():N}");
        File.WriteAllText(outside, "untouched");
        try
        {
            var link = Path.Join(Folder, "api-key");
            try
            {
                File.CreateSymbolicLink(link, outside);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return; // Windows without the symbolic-link privilege or developer mode: nothing to check.
            }

            SetText("api-key", "value");
            using var writer = CreateWriter("api-key");
            await writer.PullSecretsAsync();
            writer.WriteProtectedSecretFiles(Folder);

            Assert.Equal("untouched", File.ReadAllText(outside));
            Assert.Null(new FileInfo(link).LinkTarget);
            Assert.Equal("value", Decrypt(File.ReadAllText(link), "api-key"));
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Fact]
    public async Task OnLinuxAndMacOs_FilesAndNewFoldersAreWritableByTheirOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
            return;

        SetText("api-key", "value");
        using var writer = CreateWriter("api-key");
        await writer.PullSecretsAsync();
        var folder = Path.Join(Folder, "new");
        writer.WriteProtectedSecretFiles(folder);
        writer.WriteJsonSecrets(Path.Join(folder, "secrets.json"));

        const UnixFileMode groupOrOtherWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(folder) & groupOrOtherWrite);
        Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(Path.Join(folder, "api-key")) & groupOrOtherWrite);
        Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(Path.Join(folder, "secrets.json")) & groupOrOtherWrite);
        Assert.True(File.GetUnixFileMode(Path.Join(folder, "api-key")).HasFlag(UnixFileMode.OtherRead));
    }

    protected override IEnumerable<string> Reads => _store.Reads;

    [Fact]
    public async Task ANameWithoutAKey_ReadsTheWholeValue_OrTheDefaultKeyWhenThereIsOne()
    {
        _store.Set("app", """{"value":"s3cret"}""");
        using var whole = new FakeWriter(Protector, ["app"], _store);
        using var byDefault = new FakeWriter(Protector, ["app"], _store, defaultKey: "value");

        await whole.PullSecretsAsync();
        await byDefault.PullSecretsAsync();

        Assert.Equal("""{"value":"s3cret"}""", Decrypt(whole.ProtectedSecrets["app"], "app"));
        Assert.Equal("s3cret", Decrypt(byDefault.ProtectedSecrets["app"], "app"));
    }

    [Fact]
    public async Task ASecretIsReadOnce_ForItsWholeValueAndItsKeys()
    {
        _store.Set("prod/app", """{"user":"app"}""");
        using var writer = new FakeWriter(Protector, ["prod/app", "prod/app#user"], _store);

        await writer.PullSecretsAsync();

        Assert.Equal(["prod/app"], _store.Reads);
        Assert.Equal("""{"user":"app"}""", Decrypt(writer.ProtectedSecrets["prod__app"], "prod__app"));
        Assert.Equal("app", Decrypt(writer.ProtectedSecrets["prod__app__user"], "prod__app__user"));
    }

    [Fact]
    public async Task AValueThatIsntUtf8Text_IsRefused()
    {
        _store.Secrets["binary"] = [0xFF, 0xFE, 0x00, 0x80];
        using var writer = new FakeWriter(Protector, ["binary"], _store);

        await Assert.ThrowsAsync<InvalidDataException>(() => writer.PullSecretsAsync());
        Assert.Empty(writer.ProtectedSecrets);
    }

    [Fact]
    public async Task AWhitespaceValue_HoldsNoKeys()
    {
        _store.Set("blank", "   ");
        using var writer = new FakeWriter(Protector, ["blank#key"], _store);

        await Assert.ThrowsAsync<KeyNotFoundException>(() => writer.PullSecretsAsync());
    }

    [Fact]
    public void ThroughTheInterface_DisposingDisposesTheStore()
    {
        var writer = new FakeWriter(Protector, ["app"], _store);

        ((ISecretPipelineWriter)writer).Dispose();

        Assert.True(writer.Disposed);
    }

    [Theory]
    [InlineData("prod/app#password", "prod__app__password")]
    [InlineData("prod/app", "prod__app")]
    [InlineData("app", "app")]
    public void GetFileName_ReplacesEachSeparator(string secretName, string fileName)
        => Assert.Equal(fileName, SecretPipelineWriter.GetFileName(secretName));

    [Fact]
    public void NamesMappingToOneFileName_AreRefused()
        => Assert.Throws<ArgumentException>(() => new FakeWriter(Protector, ["a/b", "a#b"], _store));

    [Fact]
    public void Constructor_ChecksTheDefaultKeyAndTheNameRule()
    {
        Assert.Throws<ArgumentNullException>(() => SecretPipelineWriter.GetFileName(null!));
        Assert.Throws<ArgumentException>(() => new FakeWriter(Protector, ["app"], _store, defaultKey: ""));
        Assert.Throws<ArgumentException>(() => new FakeWriter(Protector, ["app"], _store, defaultKey: "a#b"));
        Assert.Throws<ArgumentNullException>(() => new NullRuleWriter(Protector));
    }

    private sealed class NullRuleWriter(IPipelineDataProtector protector) : SecretPipelineWriter(protector, ["app"], null!)
    {
        protected override Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

/// <summary>Reading a body into pinned memory.</summary>
public class PinnedBodyTests
{
    [Fact]
    public async Task ReadAsync_ReadsTheWholeBody_GrowingAsNeeded()
    {
        var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { value = new string('x', 100_000) }));

        var (buffer, length) = await PinnedBody.ReadAsync(new MemoryStream(body));

        Assert.Equal(body, buffer.AsSpan(0, length).ToArray());
    }

    [Fact]
    public async Task ReadAsync_RefusesABodyOfTheMaximumOrMore()
    {
        await Assert.ThrowsAsync<InvalidDataException>(() => PinnedBody.ReadAsync(new MemoryStream(new byte[PinnedBody.MaxLength])));
        await Assert.ThrowsAsync<ArgumentNullException>(() => PinnedBody.ReadAsync(null!));
    }
}
