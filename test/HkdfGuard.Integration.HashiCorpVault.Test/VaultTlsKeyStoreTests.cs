using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HkdfGuard.Abstractions;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// Password-protected PKCS#12 trust and client key stores in <see cref="VaultTlsOptions"/>, their
/// passwords protected by a protector on the key ring.
/// </summary>
public sealed class VaultTlsKeyStoreTests : IDisposable
{
    private const string StorePassword = "store-secret";

    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("hkdfguard-keystores");

    public void Dispose() => _directory.Delete(recursive: true);

    [Fact]
    public async Task KeyStores_StandInForThePem()
    {
        var (protector, password) = await PasswordsAsync();
        using var ca = CreateCa("Store CA");
        using var client = CreateLeaf(ca, "client");
        using var server = CreateLeaf(ca, "vault.test");
        var tls = new VaultTlsOptions
        {
            TrustStoreFile = Store("trust.p12", PublicOnly(ca)),
            TrustStorePassword = password,
            ClientKeyStoreFile = Store("client.p12", client, PublicOnly(ca)),
            ClientKeyStorePassword = password,
            PasswordProtector = protector,
        };
        Assert.False(tls.IsEmpty);

        var handler = Apply(tls);
        var validate = handler.SslOptions.RemoteCertificateValidationCallback!;
        Assert.True(validate(this, PublicOnly(server), null, SslPolicyErrors.RemoteCertificateChainErrors));
        using var stranger = CreateCa("Stranger");
        Assert.False(validate(this, PublicOnly(stranger), null, SslPolicyErrors.RemoteCertificateChainErrors));

        var presented = Assert.IsType<X509Certificate2>(handler.SslOptions.LocalCertificateSelectionCallback!(this, "vault.test", [], null, []));
        Assert.Equal(client.Thumbprint, presented.Thumbprint);
        Assert.True(presented.HasPrivateKey);
    }

    [Fact]
    public async Task AKeyStore_NeedsItsPassword_ProtectedByThePasswordProtector()
    {
        var (protector, password) = await PasswordsAsync();
        using var ca = CreateCa("Store CA");
        using var client = CreateLeaf(ca, "client");
        var keys = Store("refusals.p12", client, PublicOnly(ca));
        VaultTlsOptions KeyStore(string? protectedPassword) => new()
        {
            ClientKeyStoreFile = keys, ClientKeyStorePassword = protectedPassword, PasswordProtector = protector,
        };

        AssertRefused(KeyStore(null));
        AssertRefused(new VaultTlsOptions { ClientKeyStoreFile = keys, ClientKeyStorePassword = password });
        var otherRing = (await TestRing.CreateAsync()).CreateProtector(VaultTlsOptions.PasswordPurpose);
        AssertRefused(KeyStore(VaultTlsOptions.ProtectPassword(otherRing, StorePassword)));
        var otherPurpose = (await TestRing.CreateAsync()).CreateProtector(VaultClient.TokenPurpose);
        AssertRefused(KeyStore(VaultTlsOptions.ProtectPassword(otherPurpose, StorePassword)));
        // The password itself, never protected: refused without quoting it.
        var unprotected = AssertRefused(KeyStore(StorePassword));
        Assert.DoesNotContain(StorePassword, unprotected.Message, StringComparison.Ordinal);
        Assert.Null(unprotected.InnerException);
        AssertRefused(KeyStore(VaultTlsOptions.ProtectPassword(protector, "wrong")));
        var withPem = KeyStore(password);
        withPem.ClientCertificatePem = "-----BEGIN CERTIFICATE-----"u8.ToArray();
        AssertRefused(withPem);
        AssertRefused(new VaultTlsOptions
        {
            ClientKeyStoreFile = Path.Combine(_directory.FullName, "missing.p12"), ClientKeyStorePassword = password, PasswordProtector = protector,
        });
        Apply(KeyStore(password));

        VaultTlsOptions TrustStore(string file) => new() { TrustStoreFile = file, TrustStorePassword = password, PasswordProtector = protector };
        AssertRefused(new VaultTlsOptions { TrustStoreFile = keys, PasswordProtector = protector });
        var withCaPem = TrustStore(keys);
        withCaPem.ServerCertificatePem = "-----BEGIN CERTIFICATE-----"u8.ToArray();
        AssertRefused(withCaPem);
        AssertRefused(TrustStore(Store("no-ca.p12", client)));
        Apply(TrustStore(keys));
    }

    [Fact]
    public async Task AClientKeyStoreWithMoreThanOneKey_NeedsTheThumbprintToPresent()
    {
        var (protector, password) = await PasswordsAsync();
        using var ca = CreateCa("Store CA");
        using var first = CreateLeaf(ca, "first");
        using var second = CreateLeaf(ca, "second");
        var keys = Store("two-keys.p12", first, second);
        VaultTlsOptions Tls(string? thumbprint) => new()
        {
            ClientKeyStoreFile = keys, ClientKeyStorePassword = password, PasswordProtector = protector, ClientKeyStoreThumbprint = thumbprint,
        };

        AssertRefused(Tls(null));
        AssertRefused(Tls(ca.Thumbprint));
        var presented = Apply(Tls(second.Thumbprint.ToLowerInvariant())).SslOptions.LocalCertificateSelectionCallback!(this, "vault.test", [], null, []);
        Assert.Equal(second.Thumbprint, Assert.IsType<X509Certificate2>(presented).Thumbprint);
        AssertRefused(new VaultTlsOptions
        {
            ClientKeyStoreFile = Store("only-ca.p12", PublicOnly(ca)), ClientKeyStorePassword = password, PasswordProtector = protector,
        });
    }

    [Fact]
    public async Task ProtectPassword_ProtectsWithThePasswordProtector_AndRefusesNoPassword()
    {
        var (protector, password) = await PasswordsAsync();

        Assert.DoesNotContain(StorePassword, password, StringComparison.Ordinal);
        var decrypted = new char[protector.GetMaxDecryptedLength(password)];
        Assert.Equal(StorePassword, new string(decrypted, 0, protector.Decrypt(password, decrypted)));
        Assert.Throws<ArgumentException>("password", () => VaultTlsOptions.ProtectPassword(protector, ""));
        Assert.Throws<ArgumentNullException>(() => VaultTlsOptions.ProtectPassword(null!, StorePassword));
    }

    [Fact]
    public void KeyStores_AreNotEmptyOptions()
    {
        Assert.False(new VaultTlsOptions { TrustStoreFile = "trust.p12" }.IsEmpty);
        Assert.False(new VaultTlsOptions { ClientKeyStoreFile = "client.p12" }.IsEmpty);
        Assert.True(new VaultTlsOptions { TrustStorePassword = "x", ClientKeyStoreThumbprint = "AB" }.IsEmpty);
    }

    private static async Task<(IDataProtector Protector, string Password)> PasswordsAsync()
    {
        var protector = (await TestRing.CreateAsync()).CreateProtector(VaultTlsOptions.PasswordPurpose);
        return (protector, VaultTlsOptions.ProtectPassword(protector, StorePassword));
    }

    private static ArgumentException AssertRefused(VaultTlsOptions tls) => Assert.Throws<ArgumentException>(() => Apply(tls));

    private static SocketsHttpHandler Apply(VaultTlsOptions tls)
    {
        var handler = new SocketsHttpHandler();
        tls.ApplyTo(handler, supplied: false);
        return handler;
    }

    // A PKCS#12 file of certificates, protected by StorePassword.
    private string Store(string name, params X509Certificate2[] certificates)
    {
        var file = Path.Combine(_directory.FullName, name);
        File.WriteAllBytes(file, new X509Certificate2Collection(certificates).Export(X509ContentType.Pkcs12, StorePassword)!);
        return file;
    }

    private static X509Certificate2 PublicOnly(X509Certificate2 certificate) => X509CertificateLoader.LoadCertificate(certificate.RawData);

    private static X509Certificate2 CreateCa(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    // A certificate the CA issued to dnsName, with its private key.
    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string dnsName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dnsName);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(12), RandomNumberGenerator.GetBytes(8));
        return certificate.CopyWithPrivateKey(key);
    }
}
