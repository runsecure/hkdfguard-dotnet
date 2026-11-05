namespace HkdfGuard.SystemdCredentials.Test;

public sealed class SystemdCredentialSourceTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("hkdfguard-systemd-").FullName;
    private readonly string _loaded;
    private readonly FakeSystemdCreds _creds = new();
    private readonly SystemdCredentials _credentials;

    public SystemdCredentialSourceTests()
    {
        _loaded = Directory.CreateDirectory(Path.Join(_folder, "loaded")).FullName;
        _credentials = new SystemdCredentials(null, _creds);
    }

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private async Task<string> EncryptedFile(string name, string value)
    {
        var path = Path.Join(_folder, $"{name}.cred");
        await _credentials.EncryptAsync(name, value.AsMemory(), path);
        return path;
    }

    [Fact]
    public async Task AnEncryptedFile_IsDecryptedBySystemdCreds_ForEveryLookup()
    {
        var source = new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["tls-password"] = await EncryptedFile("tls-password", "pässwörd") }, _loaded);

        Assert.True(source.TryGetMaxDecryptedLength("tls-password", out var max));
        var chars = new char[max];
        Assert.Equal("pässwörd", new string(chars, 0, source.Decrypt("tls-password", chars)));
        var bytes = new byte[max];
        Assert.Equal("pässwörd"u8.ToArray(), bytes.AsSpan(0, source.Decrypt("tls-password", bytes)).ToArray());
        Assert.Equal("pässwörd", new string(chars, 0, await source.DecryptAsync("tls-password", chars.AsMemory())));
        Assert.Equal(10, await source.DecryptAsync("tls-password", bytes.AsMemory()));
        Assert.Equal(max, await source.GetMaxDecryptedLengthAsync("tls-password"));

        // Every value read is a systemd-creds run; a length isn't.
        Assert.Equal(4, _creds.Runs.Count(r => r.Arguments.Contains("decrypt")));
    }

    [Fact]
    public async Task ALoadedCredential_IsReadFirst_WithoutSystemdCreds()
    {
        await File.WriteAllTextAsync(Path.Join(_loaded, "tls-password"), "from-systemd");
        var source = new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["tls-password"] = await EncryptedFile("tls-password", "from-file") }, _loaded);

        var chars = new char[64];
        Assert.Equal("from-systemd", new string(chars, 0, source.Decrypt("tls-password", chars)));
        Assert.Equal("from-systemd", new string(chars, 0, await source.DecryptAsync("tls-password", chars.AsMemory())));
        Assert.DoesNotContain(_creds.Runs, r => r.Arguments.Contains("decrypt"));
    }

    [Fact]
    public void OnlyLoadedCredentials_NeedNoSystemdCredentials()
    {
        File.WriteAllText(Path.Join(_loaded, "tls-password"), "s3cret");
        var source = new SystemdCredentialSource(credentialsDirectory: _loaded);

        Assert.True(source.TryGetMaxDecryptedLength("tls-password", out var max));
        Assert.Equal(6, source.Decrypt("tls-password", new byte[max]));
    }

    [Fact]
    public async Task AMissingOrInvalidName_IsReportedMissing()
    {
        var source = new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["gone"] = Path.Join(_folder, "gone.cred") }, _loaded);

        foreach (var name in new[] { "absent", "gone", "../etc" })
        {
            Assert.False(source.TryGetMaxDecryptedLength(name, out var max));
            Assert.Equal(0, max);
            Assert.Equal(0, source.Decrypt(name, new char[8]));
            Assert.Equal(0, source.Decrypt(name, new byte[8]));
            Assert.Equal(0, await source.DecryptAsync(name, new char[8].AsMemory()));
            Assert.Equal(0, await source.DecryptAsync(name, new byte[8].AsMemory()));
            Assert.Equal(0, await source.GetMaxDecryptedLengthAsync(name));
        }

        Assert.Throws<ArgumentNullException>(() => source.Decrypt(null!, new char[8]));
    }

    [Fact]
    public async Task AResultTooSmall_IsRefused()
    {
        var source = new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["item"] = await EncryptedFile("item", "s3cret") });

        Assert.Throws<ArgumentException>(() => source.Decrypt("item", new char[3]));
        Assert.Throws<ArgumentException>(() => source.Decrypt("item", new byte[3]));
    }

    [Fact]
    public void TheEncryptedFiles_AreChecked()
    {
        Assert.Throws<ArgumentException>(() => new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["a b"] = Path.Join(_folder, "x") }));
        Assert.Throws<ArgumentException>(() => new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["item"] = "relative.cred" }));
        Assert.Throws<ArgumentException>(() => new SystemdCredentialSource(_credentials, new Dictionary<string, string> { ["item"] = "" }));
        Assert.Throws<ArgumentException>(() => new SystemdCredentialSource(null, new Dictionary<string, string> { ["item"] = Path.Join(_folder, "x") }));
    }
}

/// <summary>A test that runs the real systemd-creds: on Linux, and only when HKDFGUARD_TEST_SYSTEMD_CREDS is 1.</summary>
public sealed class SystemdCredsFactAttribute : FactAttribute
{
    public SystemdCredsFactAttribute()
    {
        if (!OperatingSystem.IsLinux() || Environment.GetEnvironmentVariable("HKDFGUARD_TEST_SYSTEMD_CREDS") != "1")
            Skip = "Runs the real systemd-creds: set HKDFGUARD_TEST_SYSTEMD_CREDS to 1 on Linux, as root or with --user credentials.";
    }
}

public sealed class SystemdCredentialsIntegrationTests
{
    [SystemdCredsFact]
    public async Task ARealCredential_RoundTripsThroughSystemdCreds_AndOnlyUnderItsName()
    {
        var folder = Directory.CreateTempSubdirectory("hkdfguard-systemd-").FullName;
        try
        {
            var credentials = new SystemdCredentials(new SystemdCredentialsOptions
            {
                Key = SystemdCredentialKey.Host,
                UserScope = Environment.UserName != "root",
            });
            var path = Path.Join(folder, "tls-password.cred");

            await credentials.EncryptAsync("tls-password", "pässwörd".AsMemory(), path);
            using var value = await credentials.DecryptAsync("tls-password", path);

            Assert.Equal("pässwörd"u8.ToArray(), value.Value.ToArray());
            var encrypted = await File.ReadAllBytesAsync(path);
            Assert.Equal(-1, encrypted.AsSpan().IndexOf("pässwörd"u8));
            await Assert.ThrowsAsync<InvalidOperationException>(() => credentials.DecryptAsync("db-password", path));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }
}
