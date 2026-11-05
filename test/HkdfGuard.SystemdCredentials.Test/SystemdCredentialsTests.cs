using System.Text;

namespace HkdfGuard.SystemdCredentials.Test;

/// <summary>
/// Stands in for systemd-creds: records each run, and "encrypts" a credential into a file bound to
/// its name, which it "decrypts" only under that name - as systemd-creds refuses a renamed one.
/// </summary>
internal sealed class FakeSystemdCreds : ISystemdCredsRunner
{
    public List<(string Executable, string[] Arguments, byte[] Stdin, TimeSpan Timeout)> Runs { get; } = [];

    /// <summary>When set, every run fails with this exit code and stderr.</summary>
    public (int ExitCode, string Error)? Fail { get; set; }

    public async Task<SystemdCredsResult> RunAsync(string executablePath, IReadOnlyList<string> arguments, ReadOnlyMemory<byte> stdin,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Runs.Add((executablePath, arguments.ToArray(), stdin.ToArray(), timeout));
        if (Fail is { } fail)
            return new SystemdCredsResult(fail.ExitCode, await Output([]), fail.Error);

        var name = arguments.Single(a => a.StartsWith("--name=", StringComparison.Ordinal))["--name=".Length..];
        if (arguments.Contains("encrypt"))
        {
            Assert.Equal("-", arguments[^2]);
            await File.WriteAllTextAsync(arguments[^1], $"{name}:{Convert.ToBase64String(stdin.Span)}", cancellationToken);
            return new SystemdCredsResult(0, await Output([]), "");
        }

        Assert.Equal("-", arguments[^1]);
        var stored = (await File.ReadAllTextAsync(arguments[^2], cancellationToken)).Split(':');
        if (stored[0] != name)
            return new SystemdCredsResult(1, await Output([]), $"Embedded credential name '{stored[0]}' does not match filename '{name}', refusing.\n");

        return new SystemdCredsResult(0, await Output(Convert.FromBase64String(stored[1])), "");
    }

    private static Task<SystemdCredential> Output(byte[] bytes) => SystemdCredential.ReadAsync(new MemoryStream(bytes), CancellationToken.None);
}

public sealed class SystemdCredentialsTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("hkdfguard-systemd-").FullName;
    private readonly FakeSystemdCreds _creds = new();

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private SystemdCredentials Credentials(SystemdCredentialsOptions? options = null) => new(options, _creds);

    private string PathFor(string name) => Path.Join(_folder, name);

    [Fact]
    public async Task Encrypt_WritesThePlaintextToStdin_AndTheFileIsSystemdCredsOwn()
    {
        var path = PathFor("tls-password.cred");

        await Credentials().EncryptAsync("tls-password", "pässwörd".AsMemory(), path);

        var run = Assert.Single(_creds.Runs);
        Assert.Equal("/usr/bin/systemd-creds", run.Executable);
        Assert.Equal(["--name=tls-password", "--with-key=auto", "encrypt", "-", path], run.Arguments);
        Assert.Equal("pässwörd"u8.ToArray(), run.Stdin);
        Assert.Equal(TimeSpan.FromSeconds(30), run.Timeout);
        Assert.True(File.Exists(path));
    }

    [Theory]
    [InlineData(SystemdCredentialKey.Auto, "auto")]
    [InlineData(SystemdCredentialKey.Host, "host")]
    [InlineData(SystemdCredentialKey.Tpm2, "tpm2")]
    [InlineData(SystemdCredentialKey.HostAndTpm2, "host+tpm2")]
    public async Task Encrypt_UsesTheKeyAndScopeAsked(SystemdCredentialKey key, string argument)
    {
        var options = new SystemdCredentialsOptions { Key = key, UserScope = true, ExecutablePath = "/usr/local/bin/systemd-creds", Timeout = TimeSpan.FromSeconds(5) };

        await Credentials(options).EncryptAsync("item", "v"u8.ToArray(), PathFor("item.cred"));

        var run = Assert.Single(_creds.Runs);
        Assert.Equal(["--name=item", $"--with-key={argument}", "--user", "encrypt", "-", PathFor("item.cred")], run.Arguments);
        Assert.Equal(("/usr/local/bin/systemd-creds", TimeSpan.FromSeconds(5)), (run.Executable, run.Timeout));
    }

    [Fact]
    public async Task Decrypt_ReadsTheValueFromStdout_IntoACredentialThatZeroesOnDispose()
    {
        var credentials = Credentials();
        await credentials.EncryptAsync("tls-password", "s3cret".AsMemory(), PathFor("tls-password.cred"));

        var value = await credentials.DecryptAsync("tls-password", PathFor("tls-password.cred"));

        Assert.Equal(["--name=tls-password", "--newline=no", "decrypt", PathFor("tls-password.cred"), "-"], _creds.Runs[^1].Arguments);
        Assert.Empty(_creds.Runs[^1].Stdin);
        Assert.Equal("s3cret"u8.ToArray(), value.Value.ToArray());
        Assert.Equal(6, value.Length);

        value.Dispose();
        value.Dispose();
        Assert.Throws<ObjectDisposedException>(() => value.Value.Length);
    }

    [Fact]
    public async Task Decrypt_InUserScope_AsksForIt()
    {
        var credentials = Credentials(new SystemdCredentialsOptions { UserScope = true });
        await credentials.EncryptAsync("item", "v"u8.ToArray(), PathFor("item.cred"));

        using var value = await credentials.DecryptAsync("item", PathFor("item.cred"));

        Assert.Equal(["--name=item", "--newline=no", "--user", "decrypt", PathFor("item.cred"), "-"], _creds.Runs[^1].Arguments);
    }

    [Fact]
    public async Task ARenamedCredential_FailsToDecrypt_WithSystemdCredsMessage()
    {
        var credentials = Credentials();
        await credentials.EncryptAsync("tls-password", "s3cret"u8.ToArray(), PathFor("tls-password.cred"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => credentials.DecryptAsync("db-password", PathFor("tls-password.cred")));

        Assert.Equal("systemd-creds decrypt failed with exit code 1: Embedded credential name 'tls-password' does not match filename 'db-password', refusing.", ex.Message);
    }

    [Fact]
    public async Task AFailureWithoutAMessage_GivesTheExitCode()
    {
        _creds.Fail = (243, " ");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => Credentials().EncryptAsync("item", "v"u8.ToArray(), PathFor("item.cred")));

        Assert.Equal("systemd-creds encrypt failed with exit code 243", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("-n")]
    [InlineData("a/b")]
    [InlineData("a b")]
    [InlineData(null)]
    public async Task AnInvalidName_IsRefused_BeforeSystemdCredsRuns(string? name)
    {
        Assert.False(SystemdCredentials.IsValidName(name));
        await Assert.ThrowsAsync<ArgumentException>(() => Credentials().EncryptAsync(name!, "v"u8.ToArray(), PathFor("x.cred")));
        await Assert.ThrowsAsync<ArgumentException>(() => Credentials().DecryptAsync(name!, PathFor("x.cred")));
        Assert.Empty(_creds.Runs);
    }

    [Fact]
    public void AValidName_HoldsLettersDigitsDotsUnderscoresAndHyphens()
    {
        Assert.True(SystemdCredentials.IsValidName("tls.pfx_password-2"));
        Assert.True(SystemdCredentials.IsValidName(new string('a', SystemdCredentials.MaxNameLength)));
        Assert.False(SystemdCredentials.IsValidName(new string('a', SystemdCredentials.MaxNameLength + 1)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative/item.cred")]
    public async Task ARelativePath_IsRefused(string path)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Credentials().EncryptAsync("item", "v"u8.ToArray(), path));
        await Assert.ThrowsAsync<ArgumentException>(() => Credentials().DecryptAsync("item", path));
    }

    [Fact]
    public void TheOptions_AreChecked()
    {
        Assert.Throws<ArgumentException>(() => Credentials(new SystemdCredentialsOptions { ExecutablePath = "systemd-creds" }));
        Assert.Throws<ArgumentException>(() => Credentials(new SystemdCredentialsOptions { ExecutablePath = "" }));
        Assert.Throws<ArgumentException>(() => Credentials(new SystemdCredentialsOptions { Key = (SystemdCredentialKey)9 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Credentials(new SystemdCredentialsOptions { Timeout = TimeSpan.Zero }));
    }

    [Fact]
    public void ThePublicConstructor_IsLinuxOnly()
    {
        SystemdCredentials.RequireLinux(isLinux: true);
        Assert.Throws<PlatformNotSupportedException>(() => SystemdCredentials.RequireLinux(isLinux: false));

        if (OperatingSystem.IsLinux())
            _ = new SystemdCredentials();
        else
            Assert.Throws<PlatformNotSupportedException>(() => new SystemdCredentials());
    }

    [Fact]
    public void ALoadedCredential_IsReadFromTheCredentialsDirectory()
    {
        File.WriteAllText(PathFor("tls-password"), "s3cret");

        using var value = SystemdCredentials.ReadLoadedCredential("tls-password", _folder);

        Assert.Equal("s3cret"u8.ToArray(), value!.Value.ToArray());
        Assert.Null(SystemdCredentials.ReadLoadedCredential("absent", _folder));
        Assert.Throws<ArgumentException>(() => SystemdCredentials.ReadLoadedCredential("../etc", _folder));
    }

    [Fact]
    public void WithoutACredentialsDirectory_NothingIsLoaded()
    {
        var previous = Environment.GetEnvironmentVariable(SystemdCredentials.CredentialsDirectoryVariable);
        Environment.SetEnvironmentVariable(SystemdCredentials.CredentialsDirectoryVariable, null);
        try
        {
            Assert.Null(SystemdCredentials.ReadLoadedCredential("tls-password"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(SystemdCredentials.CredentialsDirectoryVariable, previous);
        }
    }

    [Fact]
    public async Task AValue_GrowsAsItIsRead_UpToSystemdsLimit()
    {
        var large = new byte[SystemdCredential.MaxLength];
        Random.Shared.NextBytes(large);

        using var value = await SystemdCredential.ReadAsync(new MemoryStream(large), CancellationToken.None);
        Assert.Equal(large, value.Value.ToArray());

        await Assert.ThrowsAsync<InvalidDataException>(() => SystemdCredential.ReadAsync(new MemoryStream(new byte[SystemdCredential.MaxLength + 1]), CancellationToken.None));
    }

    [Fact]
    public void AFileOverSystemdsLimit_IsRefused()
    {
        using (var file = File.Create(PathFor("big")))
            file.SetLength(SystemdCredential.MaxLength + 1);

        Assert.Throws<InvalidDataException>(() => SystemdCredentials.ReadLoadedCredential("big", _folder));
    }

    [Fact]
    public void AFileThatCantBeRead_IsRefused()
    {
        File.WriteAllText(PathFor("write-only"), "s3cret");
        using var handle = File.OpenHandle(PathFor("write-only"), FileMode.Open, FileAccess.Write);

        Assert.ThrowsAny<Exception>(() => SystemdCredential.ReadFile(handle));
    }

    [Fact]
    public async Task AFailingRead_ZeroesWhatItHad()
    {
        await Assert.ThrowsAsync<IOException>(() => SystemdCredential.ReadAsync(new FailingStream(), CancellationToken.None));
    }

    private sealed class FailingStream : MemoryStream
    {
        private bool _readOnce;

        public FailingStream()
            : base(Encoding.ASCII.GetBytes("partial"))
        {
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_readOnce)
                throw new IOException("lost");
            _readOnce = true;
            return base.ReadAsync(buffer, cancellationToken);
        }
    }
}
