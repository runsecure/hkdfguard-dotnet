using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.Options.Certificate.Test;

public class CertificateOptionsValidatorTests
{
    private const string Subject = "CN=api.example.com, O=Contoso";

    // An absolute path on the host the tests run on, as the validator checks it.
    private static readonly string AbsolutePath = Path.GetFullPath(Path.Join(Path.GetTempPath(), "tls.pfx"));

    private static IList<string> Failures(CertificateOptions options, OSPlatform platform)
    {
        var result = new CertificateOptionsValidator(platform).Validate(null, options);
        return result.Succeeded ? [] : result.Failures!.ToList();
    }

    private static CertificateOptions WindowsStore(string? subject = Subject)
        => new() { Windows = new CertificateStoreOptions { Subject = subject } };

    private static CertificateOptions MacOSStore(string? subject = Subject)
        => new() { MacOS = new CertificateStoreOptions { Subject = subject } };

    private static CertificateOptions ProtectedFile()
        => new() { File = new CertificateFileOptions { Path = AbsolutePath, PasswordSecretName = "tls-pfx-password" } };

    [Fact]
    public void EachSource_IsValid_OnItsOwnPlatform()
    {
        Assert.Empty(Failures(WindowsStore(), OSPlatform.Windows));
        Assert.Empty(Failures(MacOSStore(), OSPlatform.OSX));
        Assert.Empty(Failures(new CertificateOptions
        {
            Linux = new LinuxOpenSslProviderOptions { KeyUri = "handle:0x81000001", CertificateFile = AbsolutePath },
        }, OSPlatform.Linux));
        Assert.Empty(Failures(ProtectedFile(), OSPlatform.Windows));
        Assert.Empty(Failures(ProtectedFile(), OSPlatform.Linux));
        Assert.Empty(Failures(ProtectedFile(), OSPlatform.OSX));
    }

    [Theory]
    [InlineData("Windows", "Linux")]
    [InlineData("MacOS", "Windows")]
    [InlineData("Linux", "OSX")]
    public void ANativeSource_IsRefused_OnAnotherPlatform(string source, string platform)
    {
        var options = source switch
        {
            "Windows" => WindowsStore(),
            "MacOS" => MacOSStore(),
            _ => new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { KeyUri = "handle:0x81000001", CertificateFile = AbsolutePath } },
        };

        var failure = Assert.Single(Failures(options, OSPlatform.Create(platform.ToUpperInvariant())));

        Assert.StartsWith($"The {source} certificate source can only be used on {source}", failure);
    }

    [Fact]
    public void AnUnknownPlatform_IsNamedAsItIs()
        => Assert.Contains("this is FREEBSD", Assert.Single(Failures(WindowsStore(), OSPlatform.FreeBSD)));

    [Fact]
    public void NoSource_OrMoreThanOne_IsRefused()
    {
        Assert.Contains("One certificate source is required", Assert.Single(Failures(new CertificateOptions(), OSPlatform.Windows)));

        var both = WindowsStore();
        both.File = ProtectedFile().File;
        Assert.Contains(Failures(both, OSPlatform.Windows), f => f.Contains("but Windows, File are"));
    }

    [Theory]
    [InlineData("CN=api.example.com")]
    [InlineData("CN=api.example.com, O=Contoso, C=US")]
    [InlineData("cn=api.example.com")]
    public void AStore_TakesASubjectDistinguishedName(string subject)
    {
        Assert.Empty(Failures(WindowsStore(subject), OSPlatform.Windows));
        Assert.Empty(Failures(MacOSStore(subject), OSPlatform.OSX));
    }

    [Theory]
    [InlineData("3A1F5B2C9D4E6F708192A3B4C5D6E7F801234567")]                         // SHA-1
    [InlineData("3a 1f 5b 2c 9d 4e 6f 70 81 92 a3 b4 c5 d6 e7 f8 01 23 45 67")]       // as copied, spaced and lower-case
    [InlineData("‎3A:1F:5B:2C:9D:4E:6F:70:81:92:A3:B4:C5:D6:E7:F8:01:23:45:67")] // with Windows' invisible mark and colons
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")] // SHA-256
    public void AThumbprint_PinsAStore_WithoutASubject(string thumbprint)
    {
        Assert.Empty(Failures(new CertificateOptions { Thumbprint = thumbprint, Windows = new CertificateStoreOptions() }, OSPlatform.Windows));
        Assert.Empty(Failures(new CertificateOptions { Thumbprint = thumbprint, MacOS = new CertificateStoreOptions { Subject = Subject } }, OSPlatform.OSX));
        Assert.Empty(Failures(new CertificateOptions { Thumbprint = thumbprint, File = ProtectedFile().File }, OSPlatform.Linux));
    }

    [Theory]
    [InlineData("")]
    [InlineData("3A1F5B2C")]                                      // too short
    [InlineData("3A1F5B2C9D4E6F708192A3B4C5D6E7F80123456")]       // 39 digits
    [InlineData("ZZ1F5B2C9D4E6F708192A3B4C5D6E7F801234567")]      // not hex
    [InlineData("CN=api.example.com")]
    public void AThumbprint_ThatIsntOne_IsRefused(string thumbprint)
    {
        var failure = Assert.Single(Failures(new CertificateOptions { Thumbprint = thumbprint, Windows = new CertificateStoreOptions { Subject = Subject } }, OSPlatform.Windows));
        Assert.StartsWith("Thumbprint must be", failure);
    }

    [Theory]
    [InlineData(null, "Subject is required")]
    [InlineData(" ", "Subject is required")]
    [InlineData("api.example.com", "must be a distinguished name")]
    public void AStore_NeedsASubjectThatIsADistinguishedName(string? subject, string reason)
    {
        var windows = Assert.Single(Failures(WindowsStore(subject), OSPlatform.Windows));
        var macOS = Assert.Single(Failures(MacOSStore(subject), OSPlatform.OSX));

        Assert.StartsWith("Windows.", windows);
        Assert.Contains(reason, windows);
        Assert.StartsWith("MacOS.", macOS);
        Assert.Contains(reason, macOS);
    }

    [Fact]
    public void AStore_NeedsAStoreLocationAndNameThatAreOnes()
    {
        var options = WindowsStore();
        options.Windows!.StoreLocation = (StoreLocation)7;
        options.Windows.StoreName = (StoreName)42;

        var failures = Failures(options, OSPlatform.Windows);

        Assert.Equal(2, failures.Count);
        Assert.Contains(failures, f => f.StartsWith("Windows.StoreLocation"));
        Assert.Contains(failures, f => f.StartsWith("Windows.StoreName"));
    }

    [Theory]
    [InlineData("my-provider")]
    [InlineData("my_provider")]
    public void ALinuxProvider_MayHoldHyphensAndUnderscores(string provider)
    {
        var options = new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { Provider = provider, KeyUri = "k", CertificateFile = AbsolutePath } };

        Assert.Empty(Failures(options, OSPlatform.Linux));
    }

    [Fact]
    public void ThePlatform_IsTheFirstOperatingSystemCheckThatHolds()
    {
        Assert.Equal(OSPlatform.Windows, CertificateOptionsValidator.PlatformOf(true, false, false));
        Assert.Equal(OSPlatform.OSX, CertificateOptionsValidator.PlatformOf(false, true, false));
        Assert.Equal(OSPlatform.Linux, CertificateOptionsValidator.PlatformOf(false, false, true));
        Assert.Equal(OSPlatform.FreeBSD, CertificateOptionsValidator.PlatformOf(false, false, false));
    }

    [Theory]
    [InlineData("")]
    [InlineData("tpm2;rm")]
    public void ALinuxProvider_MustBeAProvidersName(string provider)
    {
        var options = new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { Provider = provider, KeyUri = "k", CertificateFile = AbsolutePath } };

        Assert.StartsWith("Linux.Provider", Assert.Single(Failures(options, OSPlatform.Linux)));
    }

    [Fact]
    public void ALinuxKey_IsRequired_OnlyWithAPrivateKey()
    {
        var options = new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { Provider = "pkcs11", CertificateFile = AbsolutePath } };
        Assert.StartsWith("Linux.KeyUri", Assert.Single(Failures(options, OSPlatform.Linux)));

        options.RequirePrivateKey = false;
        Assert.Empty(Failures(options, OSPlatform.Linux));
    }

    [Theory]
    [InlineData(null, "is required")]
    [InlineData(" ", "is required")]
    [InlineData("relative/tls.crt", "must be an absolute path")]
    public void AFilePath_MustBeAbsolute(string? path, string reason)
    {
        var linux = new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { KeyUri = "k", CertificateFile = path } };
        var file = new CertificateOptions { File = new CertificateFileOptions { Path = path, PasswordSecretName = "p" } };

        Assert.Contains(reason, Assert.Single(Failures(linux, OSPlatform.Linux)));
        Assert.Contains(reason, Assert.Single(Failures(file, OSPlatform.Windows)));
    }

    [Fact]
    public void APemFile_NeedsAKeyPath_OnlyWithAPrivateKey()
    {
        var options = ProtectedFile();
        options.File!.Format = CertificateFileFormat.Pem;
        Assert.StartsWith("File.KeyPath", Assert.Single(Failures(options, OSPlatform.Windows)));

        options.File.KeyPath = AbsolutePath;
        Assert.Empty(Failures(options, OSPlatform.Windows));

        options.File.KeyPath = null;
        options.RequirePrivateKey = false;
        Assert.Empty(Failures(options, OSPlatform.Windows));
    }

    [Fact]
    public void AFileFormat_MustBeOne()
    {
        var options = ProtectedFile();
        options.File!.Format = (CertificateFileFormat)7;

        Assert.StartsWith("File.Format", Assert.Single(Failures(options, OSPlatform.Windows)));
    }

    [Fact]
    public void AKeyFile_NeedsAPassword_UnlessAnUnprotectedKeyIsAllowed()
    {
        var options = ProtectedFile();
        options.File!.PasswordSecretName = null;
        Assert.Contains("File.AllowUnprotectedPrivateKey", Assert.Single(Failures(options, OSPlatform.Windows)));

        options.File.AllowUnprotectedPrivateKey = true;
        Assert.Empty(Failures(options, OSPlatform.Windows));

        options.File.AllowUnprotectedPrivateKey = false;
        options.RequirePrivateKey = false;
        Assert.Empty(Failures(options, OSPlatform.Windows));
    }

    [Fact]
    public void AnEmptyPasswordSecretName_IsRefused()
    {
        var options = ProtectedFile();
        options.File!.PasswordSecretName = " ";

        Assert.StartsWith("File.PasswordSecretName can't be empty", Assert.Single(Failures(options, OSPlatform.Windows)));
    }

    [Fact]
    public void TheValidator_ChecksForTheRunningPlatform_AndNullOptions()
    {
        var validator = new CertificateOptionsValidator();

        Assert.True(validator.Validate(null, ProtectedFile()).Succeeded);
        Assert.Equal(OperatingSystem.IsWindows(), validator.Validate(null, WindowsStore()).Succeeded);
        Assert.Throws<ArgumentNullException>(() => validator.Validate(null, null!));
    }

    [Fact]
    public void TheDocumentedShapes_BindFromConfiguration()
    {
        const string json = """
            {
              "Windows": { "Certificate": { "Windows": { "StoreLocation": "CurrentUser", "StoreName": "TrustedPeople", "Subject": "CN=api.example.com" } } },
              "MacOS": { "Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } } },
              "Linux": { "Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=t", "CertificateFile": "/etc/myapp/tls.crt" } } },
              "File": { "Certificate": { "RequirePrivateKey": false, "File": { "Path": "/etc/myapp/tls.pem", "Format": "Pem", "KeyPath": "/etc/myapp/tls.key", "PasswordSecretName": "tls-key-password", "AllowUnprotectedPrivateKey": true } } }
            }
            """;
        var configuration = new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json))).Build();
        CertificateOptions Bind(string key) => configuration.GetSection($"{key}:Certificate").Get<CertificateOptions>()!;

        var windows = Bind("Windows").Windows!;
        Assert.Equal((StoreLocation.CurrentUser, StoreName.TrustedPeople, "CN=api.example.com"), (windows.StoreLocation, windows.StoreName, windows.Subject));

        var macOS = Bind("MacOS").MacOS!;
        Assert.Equal((StoreLocation.LocalMachine, StoreName.My, "CN=api.example.com"), (macOS.StoreLocation, macOS.StoreName, macOS.Subject));

        var linux = Bind("Linux").Linux!;
        Assert.Equal(("pkcs11", "pkcs11:token=t", "/etc/myapp/tls.crt"), (linux.Provider, linux.KeyUri, linux.CertificateFile));

        var options = Bind("File");
        Assert.False(options.RequirePrivateKey);
        Assert.Equal((CertificateFileFormat.Pem, "/etc/myapp/tls.pem", "/etc/myapp/tls.key", "tls-key-password", true),
            (options.File!.Format, options.File.Path, options.File.KeyPath, options.File.PasswordSecretName, options.File.AllowUnprotectedPrivateKey));
    }

    [Fact]
    public void TheDefaults_AreTheSafeOnes()
    {
        var options = new CertificateOptions
        {
            Windows = new CertificateStoreOptions(),
            Linux = new LinuxOpenSslProviderOptions(),
            File = new CertificateFileOptions(),
        };

        Assert.True(options.RequirePrivateKey);
        Assert.Equal((StoreLocation.LocalMachine, StoreName.My), (options.Windows.StoreLocation, options.Windows.StoreName));
        Assert.Equal("tpm2", options.Linux.Provider);
        Assert.Equal(CertificateFileFormat.Pkcs12, options.File.Format);
        Assert.False(options.File.AllowUnprotectedPrivateKey);
    }
}
