using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Options;

namespace HkdfGuard.Options.Certificate.Test;

/// <summary>The loader against real certificates and key files the tests make, and stores they hand it.</summary>
public sealed class CertificateOptionsLoaderTests : IDisposable
{
    private const string Subject = "CN=api.example.com, O=Contoso";
    private const string Password = "pässwörd-123";

    private static readonly DateTimeOffset Now = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    private readonly string _folder = Directory.CreateTempSubdirectory("hkdfguard-certificate-").FullName;
    private readonly FakePasswords _passwords = new() { ["tls-password"] = Password };
    private readonly FixedTime _time = new(Now);

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    // A loader that validates for platform and reads the store from certificates, a fresh copy of each per read.
    private CertificateOptionsLoader Loader(OSPlatform platform, params byte[][] storeCertificates)
        => Loader(platform, OperatingSystem.IsWindows(), storeCertificates);

    private CertificateOptionsLoader Loader(OSPlatform platform, bool reimportPemKeys, params byte[][] storeCertificates)
        => new(_passwords, _time, new CertificateOptionsValidator(platform), (_, _) =>
        {
            var collection = new X509Certificate2Collection();
            foreach (var pfx in storeCertificates)
                collection.Add(X509CertificateLoader.LoadPkcs12(pfx, password: null, X509KeyStorageFlags.Exportable));
            return collection;
        }, reimportPemKeys);

    private CertificateOptionsLoader Loader(params byte[][] storeCertificates) => Loader(OSPlatform.Windows, storeCertificates);

    private static RSA NewKey() => RSA.Create(2048);

    private static X509Certificate2 SelfSigned(RSA key, string subject = Subject, int notBeforeDays = -10, int notAfterDays = 300)
        => new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(Now.AddDays(notBeforeDays), Now.AddDays(notAfterDays));

    // A store entry: the certificate with its key, or without one.
    private static byte[] StoreEntry(int notBeforeDays, int notAfterDays, bool withKey = true, string subject = Subject)
    {
        using var key = NewKey();
        using var certificate = SelfSigned(key, subject, notBeforeDays, notAfterDays);
        return withKey
            ? certificate.Export(X509ContentType.Pkcs12)
            : X509CertificateLoader.LoadCertificate(certificate.RawData).Export(X509ContentType.Pkcs12);
    }

    private string Write(string name, byte[] contents)
    {
        var path = Path.Join(_folder, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    private string Write(string name, string contents) => Write(name, Encoding.ASCII.GetBytes(contents));

    private static CertificateOptions Store(string subject = Subject, bool requirePrivateKey = true)
        => new() { Windows = new CertificateStoreOptions { Subject = subject }, RequirePrivateKey = requirePrivateKey };

    private CertificateOptions Pfx(string path, string? passwordSecretName = "tls-password", bool allowUnprotected = false, bool requirePrivateKey = true)
        => new()
        {
            File = new CertificateFileOptions { Path = path, PasswordSecretName = passwordSecretName, AllowUnprotectedPrivateKey = allowUnprotected },
            RequirePrivateKey = requirePrivateKey,
        };

    private static void AssertSigns(X509Certificate2 certificate)
    {
        using var key = certificate.GetRSAPrivateKey()!;
        var data = "to sign"u8.ToArray();
        var signature = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var publicKey = certificate.GetRSAPublicKey()!;
        Assert.True(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void AStore_GivesTheCertificateValidNowWithItsKey_ThatExpiresLast()
    {
        var expired = StoreEntry(-400, -1);
        var notYetValid = StoreEntry(1, 900);
        var newestWithoutKey = StoreEntry(-1, 800, withKey: false);
        var older = StoreEntry(-200, 100);
        var renewed = StoreEntry(-5, 400);
        var otherSubject = StoreEntry(-5, 700, subject: "CN=other.example.com");
        var disposed = new List<X509Certificate2>();
        var loader = new CertificateOptionsLoader(_passwords, _time, new CertificateOptionsValidator(OSPlatform.Windows), (name, location) =>
        {
            Assert.Equal((StoreName.My, StoreLocation.LocalMachine), (name, location));
            var collection = new X509Certificate2Collection();
            foreach (var pfx in new[] { expired, notYetValid, newestWithoutKey, older, renewed, otherSubject })
                collection.Add(X509CertificateLoader.LoadPkcs12(pfx, password: null, X509KeyStorageFlags.Exportable));
            disposed.AddRange(collection);
            return collection;
        }, reimportPemKeys: false);

        using var certificate = loader.Load(Store());

        Assert.Equal(Now.AddDays(400).UtcDateTime.Date, certificate.NotAfter.ToUniversalTime().Date);
        Assert.True(certificate.HasPrivateKey);
        AssertSigns(certificate);
        Assert.Equal(5, disposed.Count(c => c.Handle == IntPtr.Zero));
        Assert.NotEqual(IntPtr.Zero, certificate.Handle);
    }

    [Fact]
    public async Task AStore_WithoutAKeyRequired_GivesTheNewestValidOne()
    {
        var loader = Loader(StoreEntry(-200, 100), StoreEntry(-1, 800, withKey: false));

        using var certificate = loader.Load(Store(requirePrivateKey: false));
        using var loadedAsync = await loader.LoadAsync(Store(requirePrivateKey: false));

        Assert.False(certificate.HasPrivateKey);
        Assert.Equal(Now.AddDays(800).UtcDateTime.Date, certificate.NotAfter.ToUniversalTime().Date);
        Assert.Equal(certificate.Thumbprint, loadedAsync.Thumbprint);
    }

    [Fact]
    public void AStoresSubject_IsComparedWhole_IgnoringCase()
    {
        using var certificate = Loader(StoreEntry(-1, 100)).Load(Store("cn=API.example.com, o=contoso"));
        Assert.Equal(Subject, certificate.Subject);

        Assert.Throws<InvalidOperationException>(() => Loader(StoreEntry(-1, 100)).Load(Store("CN=api.example.com")));
    }

    [Fact]
    public void AStoreWithoutACertificateToGive_SaysWhy()
    {
        var none = Assert.Throws<InvalidOperationException>(() => Loader(StoreEntry(-1, 100, subject: "CN=other")).Load(Store()));
        Assert.Contains("holds no certificate whose subject is", none.Message);

        var unusable = Assert.Throws<InvalidOperationException>(() => Loader(StoreEntry(-400, -1), StoreEntry(-1, 100, withKey: false)).Load(Store()));
        Assert.Contains("2 certificate(s)", unusable.Message);
        Assert.Contains("without a private key", unusable.Message);

        var expired = Assert.Throws<InvalidOperationException>(() => Loader(StoreEntry(-400, -1)).Load(Store(requirePrivateKey: false)));
        Assert.EndsWith("expired or not yet valid.", expired.Message);
    }

    [Fact]
    public void AMacOSKeychain_IsReadAsAStore()
    {
        var options = new CertificateOptions { MacOS = new CertificateStoreOptions { StoreLocation = StoreLocation.CurrentUser, Subject = Subject } };

        using var certificate = Loader(OSPlatform.OSX, StoreEntry(-1, 100)).Load(options);

        Assert.True(certificate.HasPrivateKey);
    }

    [Fact]
    public async Task APfx_IsOpenedWithItsPassword_FromThePasswordSource()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var path = Write("tls.pfx", original.Export(X509ContentType.Pkcs12, Password));
        var loader = Loader();

        using var loaded = loader.Load(Pfx(path));
        using var loadedAsync = await loader.LoadAsync(Pfx(path));

        Assert.Equal(original.Thumbprint, loaded.Thumbprint);
        AssertSigns(loaded);
        AssertSigns(loadedAsync);
        Assert.Equal(1, _passwords.AsyncReads);
    }

    [Fact]
    public async Task ThePassword_IsZeroed_OnceTheKeyIsRead()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var path = Write("tls.pfx", original.Export(X509ContentType.Pkcs12, Password));

        using var loaded = await Loader().LoadAsync(Pfx(path));

        Assert.NotNull(_passwords.LastBuffer);
        Assert.All(_passwords.LastBuffer!.Value.ToArray(), c => Assert.Equal('\0', c));
    }

    [Fact]
    public async Task AWrongPassword_IsRefused()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var path = Write("tls.pfx", original.Export(X509ContentType.Pkcs12, "another password"));

        Assert.ThrowsAny<CryptographicException>(() => Loader().Load(Pfx(path)));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => Loader().LoadAsync(Pfx(path)));
    }

    [Fact]
    public async Task AMissingPassword_OrNoPasswordSource_IsRefused()
    {
        var path = Write("tls.pfx", StoreEntry(-1, 100));

        Assert.Throws<KeyNotFoundException>(() => Loader().Load(Pfx(path, "absent")));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => Loader().LoadAsync(Pfx(path, "absent")));

        var noSource = new CertificateOptionsLoader(timeProvider: _time);
        Assert.Throws<InvalidOperationException>(() => noSource.Load(Pfx(path)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => noSource.LoadAsync(Pfx(path)));
    }

    [Fact]
    public async Task AnUnprotectedPfx_IsOpened_WhenAllowed()
    {
        var path = Write("tls.pfx", StoreEntry(-1, 100));
        var loader = new CertificateOptionsLoader(timeProvider: _time);

        using var loaded = loader.Load(Pfx(path, passwordSecretName: null, allowUnprotected: true));
        using var loadedAsync = await loader.LoadAsync(Pfx(path, passwordSecretName: null, allowUnprotected: true));

        AssertSigns(loaded);
        AssertSigns(loadedAsync);
    }

    [Fact]
    public void APfx_NeedsItsPassword_EvenForTheCertificateAlone()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var path = Write("tls.pfx", original.Export(X509ContentType.Pkcs12, Password));

        using var loaded = Loader().Load(Pfx(path, requirePrivateKey: false));

        Assert.Equal(original.Thumbprint, loaded.Thumbprint);
    }

    [Fact]
    public void APemCertificate_WithAnEncryptedKey_IsOpenedWithItsPassword()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var options = new CertificateOptions
        {
            File = new CertificateFileOptions
            {
                Format = CertificateFileFormat.Pem,
                Path = Write("tls.crt", original.ExportCertificatePem()),
                KeyPath = Write("tls.key", key.ExportEncryptedPkcs8PrivateKeyPem(Password,
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000))),
                PasswordSecretName = "tls-password",
            },
        };

        using var loaded = Loader().Load(options);
        using var asLoaded = Loader(OSPlatform.Windows, reimportPemKeys: false).Load(options);

        Assert.Equal(original.Thumbprint, loaded.Thumbprint);
        AssertSigns(loaded);
        AssertSigns(asLoaded);
    }

    [Fact]
    public void APemCertificate_WithAPlainKey_IsOpened_WhenAllowed()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var options = new CertificateOptions
        {
            File = new CertificateFileOptions
            {
                Format = CertificateFileFormat.Pem,
                Path = Write("tls.crt", original.ExportCertificatePem()),
                KeyPath = Write("tls.key", key.ExportPkcs8PrivateKeyPem()),
                AllowUnprotectedPrivateKey = true,
            },
        };

        using var loaded = Loader().Load(options);

        AssertSigns(loaded);
    }

    [Fact]
    public void APemCertificate_Alone_NeedsNoKeyOrPassword()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var options = new CertificateOptions
        {
            File = new CertificateFileOptions { Format = CertificateFileFormat.Pem, Path = Write("ca.crt", original.ExportCertificatePem()), PasswordSecretName = "tls-password" },
            RequirePrivateKey = false,
        };

        using var loaded = Loader().Load(options);

        Assert.False(loaded.HasPrivateKey);
        Assert.Equal(0, _passwords.Reads);
    }

    [Fact]
    public void AFileCertificate_NotValidNow_OrWithoutItsKey_IsRefused()
    {
        var expired = Write("expired.pfx", StoreEntry(-400, -1));
        var keyless = Write("keyless.pfx", StoreEntry(-1, 100, withKey: false));

        var ex = Assert.Throws<InvalidOperationException>(() => Loader().Load(Pfx(expired, null, allowUnprotected: true)));
        Assert.Contains("not now", ex.Message);
        ex = Assert.Throws<InvalidOperationException>(() => Loader().Load(Pfx(keyless, null, allowUnprotected: true)));
        Assert.Contains("has no private key", ex.Message);
    }

    [Fact]
    public void ALinuxCertificate_AloneIsReadFromItsFile_ItsProviderKeyOnlyOnLinux()
    {
        using var key = NewKey();
        using var original = SelfSigned(key);
        var path = Write("tls.crt", original.ExportCertificatePem());
        var loader = Loader(OSPlatform.Linux);

        using var alone = loader.Load(new CertificateOptions { Linux = new LinuxOpenSslProviderOptions { CertificateFile = path }, RequirePrivateKey = false });
        Assert.Equal(original.Thumbprint, alone.Thumbprint);

        if (!OperatingSystem.IsLinux())
        {
            Assert.Throws<PlatformNotSupportedException>(() => loader.Load(new CertificateOptions
            {
                Linux = new LinuxOpenSslProviderOptions { CertificateFile = path, KeyUri = "handle:0x81000001" },
            }));
        }
    }

    [Fact]
    public async Task InvalidOptions_AreRefused_BeforeAnythingIsOpened()
    {
        var ex = Assert.Throws<OptionsValidationException>(() => Loader().Load(new CertificateOptions(), "tls"));
        Assert.Equal("tls", ex.OptionsName);
        Assert.Contains("One certificate source is required", ex.Message);

        var unnamed = await Assert.ThrowsAsync<OptionsValidationException>(() => Loader().LoadAsync(new CertificateOptions()));
        Assert.Equal(Microsoft.Extensions.Options.Options.DefaultName, unnamed.OptionsName);

        Assert.Throws<ArgumentNullException>(() => Loader().Load(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => Loader().LoadAsync(null!));
    }

    [Fact]
    public void TheRealStore_IsOpenedReadOnly()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var options = new CertificateOptions
        {
            Windows = new CertificateStoreOptions { StoreLocation = StoreLocation.CurrentUser, Subject = $"CN=hkdfguard-test-{Guid.NewGuid():N}" },
        };

        var ex = Assert.Throws<InvalidOperationException>(() => new CertificateOptionsLoader().Load(options));
        Assert.Contains("holds no certificate", ex.Message);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    // Passwords by name, as a protected secret source hands them over.
    private sealed class FakePasswords : Dictionary<string, string>, IProtectedReadOnlyCache
    {
        public int Reads { get; private set; }

        public int AsyncReads { get; private set; }

        public Memory<char>? LastBuffer { get; private set; }

        public int Decrypt(string name, Span<byte> result) => throw new NotSupportedException();

        public int Decrypt(string name, Span<char> result)
        {
            Reads++;
            if (!TryGetValue(name, out var value))
                return 0;
            value.AsSpan().CopyTo(result);
            return value.Length;
        }

        public bool TryGetMaxDecryptedLength(string name, out int maxLength)
        {
            maxLength = TryGetValue(name, out var value) ? value.Length : 0;
            return maxLength > 0;
        }

        public ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
        {
            AsyncReads++;
            LastBuffer = result;
            return ValueTask.FromResult(Decrypt(name, result.Span));
        }
    }
}
