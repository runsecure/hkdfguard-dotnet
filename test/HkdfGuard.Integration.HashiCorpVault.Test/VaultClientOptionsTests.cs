using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>What the client accepts as options, TLS settings, and the environment variables vault-client-go reads.</summary>
public class VaultClientOptionsTests
{
    [Theory]
    [InlineData("https://vault.example.com:8200")]
    [InlineData("http://127.0.0.1:8200")]
    [InlineData("http://localhost:8200")]
    [InlineData("http://[::1]:8200")]
    [InlineData("unix:///var/run/vault.sock")]
    public async Task AnAddressThatKeepsTheTokenPrivate_IsAccepted(string address)
    {
        var protector = await ProtectorAsync();
        using var client = new VaultClient(protector, new VaultClientOptions { Address = new Uri(address) });
    }

    [Theory]
    [InlineData("http://vault.example.com:8200")]
    [InlineData("ftp://vault.example.com")]
    [InlineData("https://user:pass@vault.example.com")]
    [InlineData("https://vault.example.com/?q=1")]
    [InlineData("https://vault.example.com/#f")]
    [InlineData("unix:///")]
    public async Task AnAddressThatWouldExposeTheToken_IsRefused(string address)
    {
        var protector = await ProtectorAsync();
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { Address = new Uri(address) }));
    }

    [Fact]
    public async Task HttpAnywhere_IsAcceptedWhenAllowed()
    {
        var protector = await ProtectorAsync();
        using var client = new VaultClient(protector, new VaultClientOptions { Address = new Uri("http://vault.example.com"), AllowUnencryptedHttp = true });
    }

    [Fact]
    public async Task ARelativeOrMissingAddress_IsRefused()
    {
        var protector = await ProtectorAsync();
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { Address = new Uri("/v1", UriKind.Relative) }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { Address = null! }));
    }

    [Fact]
    public async Task NegativeTimesAndUnsendableNamespaces_AreRefused()
    {
        var protector = await ProtectorAsync();
        Assert.Throws<ArgumentOutOfRangeException>(() => new VaultClient(protector, new VaultClientOptions { RequestTimeout = TimeSpan.FromSeconds(-1) }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new VaultClient(protector, new VaultClientOptions { Retry = { RetryWaitMin = TimeSpan.FromSeconds(-1) } }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new VaultClient(protector, new VaultClientOptions { Retry = { RetryWaitMax = TimeSpan.FromSeconds(-1) } }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { Namespace = "ns\n" }));
        Assert.Throws<ArgumentNullException>(() => new VaultClient(null!));
    }

    [Fact]
    public async Task AHandlerThatFollowsRedirects_IsRefused_EvenUnderADelegatingHandler()
    {
        var protector = await ProtectorAsync();
        using var sockets = new SocketsHttpHandler();
        using var client = new HttpClientHandler();
        using var delegating = new PassThrough { InnerHandler = new SocketsHttpHandler() };

        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = sockets }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = client }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = delegating }));
        using var ok = new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = new HttpClientHandler { AllowAutoRedirect = false } });
    }

    [Fact]
    public async Task TlsOptionsAndUnixAddresses_NeedASocketsHttpHandler()
    {
        var protector = await ProtectorAsync();

        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions
        {
            HttpMessageHandler = new FakeVault(),
            Tls = { InsecureSkipVerify = true },
        }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions
        {
            Address = new Uri("unix:///var/run/vault.sock"),
            HttpMessageHandler = new FakeVault(),
        }));
    }

    [Fact]
    public async Task NoOptions_IsTheDefaults_AndTheClientsOwnHandler_IsDisposedWhenItCantBeConfigured()
    {
        var protector = await ProtectorAsync();
        using var client = new VaultClient(protector);

        Assert.Equal(new Uri(VaultClientOptions.DefaultAddress), client.Options.Address);
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { Tls = { ServerCertificatePem = "junk"u8.ToArray() } }));
    }

    [Fact]
    public async Task AUnixAddress_ReachesVaultThroughTheSocket()
    {
        var socketPath = Path.Combine(Path.GetTempPath(), $"hkdfguard-{Guid.NewGuid():N}.sock");
        using var listener = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.Unix, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Unspecified);
        listener.Bind(new System.Net.Sockets.UnixDomainSocketEndPoint(socketPath));
        listener.Listen();
        var server = Task.Run(async () =>
        {
            using var connection = await listener.AcceptAsync();
            var buffer = new byte[8192];
            var received = 0;
            while (!Encoding.ASCII.GetString(buffer, 0, received).Contains("\r\n\r\n"))
                received += await connection.ReceiveAsync(buffer.AsMemory(received));
            await connection.SendAsync("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\nConnection: close\r\n\r\n{\"data\":{\"via\":\"socket\"}}  "u8.ToArray());
            return Encoding.ASCII.GetString(buffer, 0, received);
        });

        try
        {
            using var client = new VaultClient(await ProtectorAsync(), new VaultClientOptions { Address = new Uri("unix://" + socketPath.Replace('\\', '/')) });
            var response = await client.ReadAsync("sys/health");

            Assert.Equal("socket", response!.Data!["via"].GetString());
            Assert.StartsWith("GET /v1/sys/health HTTP/1.1", await server);
        }
        finally
        {
            File.Delete(socketPath);
        }
    }

    [Fact]
    public async Task AUnixAddress_TakesTlsOptionsToo()
    {
        var protector = await ProtectorAsync();
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };

        using var client = new VaultClient(protector, new VaultClientOptions
        {
            Address = new Uri("unix:///var/run/vault.sock"),
            HttpMessageHandler = handler,
            Tls = { ServerName = "vault.internal" },
        });

        Assert.NotNull(handler.ConnectCallback);
        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    public void FromEnvironment_ReadsTheProcessEnvironment()
    {
        var e = Record.Exception(() => VaultClientOptions.FromEnvironment());

        // Whatever this machine's VAULT_* variables hold: options, or a FormatException naming one.
        Assert.True(e is null or FormatException);
    }

    [Theory]
    [InlineData("1", true)]
    [InlineData("t", true)]
    [InlineData("T", true)]
    [InlineData("TRUE", true)]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("0", false)]
    [InlineData("f", false)]
    [InlineData("F", false)]
    [InlineData("FALSE", false)]
    [InlineData("false", false)]
    [InlineData("False", false)]
    public void FromEnvironment_ReadsBooleansAsGoDoes(string value, bool expected)
        => Assert.Equal(expected, VaultClientOptions.FromEnvironment(n => n == "VAULT_SKIP_VERIFY" ? value : null, null).Tls.InsecureSkipVerify);

    [Fact]
    public void AnIntermediateVaultSendsAlong_ChainsToTheTrustedCa()
    {
        using var root = CreateCa("Root CA");
        using var intermediate = CreateIntermediate(root, "Intermediate CA");
        using var leaf = CreateLeaf(intermediate, "vault.test");
        var validate = Apply(new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(root.ExportCertificatePem()) })
            .SslOptions.RemoteCertificateValidationCallback!;

        // What the handshake hands over: the chain as built from what Vault sent, untrusted by the system.
        using var sent = new X509Chain();
        sent.ChainPolicy.ExtraStore.Add(intermediate);
        sent.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        sent.Build(leaf);

        Assert.True(validate(this, leaf, sent, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(validate(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public async Task AUnixAddress_ConnectsThroughTheSocket()
    {
        var protector = await ProtectorAsync();
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        using var client = new VaultClient(protector, new VaultClientOptions
        {
            Address = new Uri("unix:///nonexistent/hkdfguard-test.sock"),
            HttpMessageHandler = new PassThrough { InnerHandler = handler },
            Retry = { RetryMax = 0 },
        });

        Assert.NotNull(handler.ConnectCallback);
        var e = await Assert.ThrowsAsync<HttpRequestException>(() => client.ReadAsync("sys/health"));
        Assert.IsAssignableFrom<System.Net.Sockets.SocketException>(e.InnerException);
    }

    [Fact]
    public void TlsIsEmpty_OnlyWhenNothingIsSet()
    {
        Assert.True(new VaultTlsOptions().IsEmpty);
        Assert.True(new VaultTlsOptions { ServerCertificatePem = [] }.IsEmpty);
        Assert.False(new VaultTlsOptions { ServerName = "my-server" }.IsEmpty);
        Assert.False(new VaultTlsOptions { ServerCertificateFile = "./cert.pem" }.IsEmpty);
        Assert.False(new VaultTlsOptions { ServerCertificatePem = [1, 1, 2, 3, 5] }.IsEmpty);
        Assert.False(new VaultTlsOptions { ServerCertificateDirectory = "." }.IsEmpty);
        Assert.False(new VaultTlsOptions { ClientCertificateFile = "c" }.IsEmpty);
        Assert.False(new VaultTlsOptions { ClientCertificatePem = [1] }.IsEmpty);
        Assert.False(new VaultTlsOptions { ClientCertificateKeyFile = "k" }.IsEmpty);
        Assert.False(new VaultTlsOptions { ClientCertificateKeyPem = [1] }.IsEmpty);
        Assert.False(new VaultTlsOptions { InsecureSkipVerify = true }.IsEmpty);
    }

    [Fact]
    public void InsecureSkipVerify_AcceptsAnything()
    {
        var handler = Apply(new VaultTlsOptions { InsecureSkipVerify = true });

        Assert.True(handler.SslOptions.RemoteCertificateValidationCallback!(this, null, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void ACaCertificate_IsTrusted_ForCertificatesItSigned_AndOnlyThose()
    {
        using var ca = CreateCa("Test CA");
        using var otherCa = CreateCa("Other CA");
        using var leaf = CreateLeaf(ca, "vault.test");
        using var stranger = CreateLeaf(otherCa, "vault.test");
        var handler = Apply(new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(ca.ExportCertificatePem()) });
        var validate = handler.SslOptions.RemoteCertificateValidationCallback!;

        // The system doesn't trust the test CA: chain errors are expected, and overruled.
        Assert.True(validate(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(validate(this, stranger, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(validate(this, leaf, null, SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(validate(this, null, null, SslPolicyErrors.RemoteCertificateNotAvailable));
    }

    [Fact]
    public void CaCertificates_ComeFromAFile_OrADirectory_FileFirst()
    {
        using var ca = CreateCa("Test CA");
        using var leaf = CreateLeaf(ca, "vault.test");
        var directory = Directory.CreateTempSubdirectory("hkdfguard-ca");
        try
        {
            var file = Path.Combine(directory.FullName, "ca.pem");
            File.WriteAllText(file, ca.ExportCertificatePem());

            foreach (var tls in new[]
                     {
                         new VaultTlsOptions { ServerCertificateFile = file, ServerCertificatePem = "junk"u8.ToArray() },
                         new VaultTlsOptions { ServerCertificateDirectory = directory.FullName },
                     })
                Assert.True(Apply(tls).SslOptions.RemoteCertificateValidationCallback!(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));

            File.WriteAllText(Path.Combine(directory.FullName, "notes.txt"), "not a certificate");
            Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions { ServerCertificateDirectory = directory.FullName }));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void ServerName_ReplacesTheHostTheCertificateMustName()
    {
        using var ca = CreateCa("Test CA");
        using var leaf = CreateLeaf(ca, "vault.internal");
        var pem = Encoding.UTF8.GetBytes(ca.ExportCertificatePem());

        var named = Apply(new VaultTlsOptions { ServerCertificatePem = pem, ServerName = "vault.internal" }).SslOptions.RemoteCertificateValidationCallback!;
        var misnamed = Apply(new VaultTlsOptions { ServerCertificatePem = pem, ServerName = "other.internal" }).SslOptions.RemoteCertificateValidationCallback!;
        var systemTrust = Apply(new VaultTlsOptions { ServerName = "vault.internal" }).SslOptions.RemoteCertificateValidationCallback!;

        // Connecting by IP: the name mismatch against the host is overruled by ServerName.
        Assert.True(named(this, leaf, null, SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(misnamed(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.True(systemTrust(this, leaf, null, SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(systemTrust(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void ACaPemWithoutACertificate_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions { ServerCertificatePem = "no certificate here"u8.ToArray() }));
        Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions
        {
            ServerCertificatePem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"u8.ToArray(),
        }));
    }

    [Fact]
    public void AClientCertificate_IsPresented_WhateverCasVaultAsksFor()
    {
        using var ca = CreateCa("Client CA");
        using var leaf = CreateLeaf(ca, "client", out var key);
        var certificatePem = leaf.ExportCertificatePem();
        var keyPem = key.ExportPkcs8PrivateKeyPem();
        var directory = Directory.CreateTempSubdirectory("hkdfguard-client");
        try
        {
            File.WriteAllText(Path.Combine(directory.FullName, "cert.pem"), certificatePem);
            File.WriteAllText(Path.Combine(directory.FullName, "key.pem"), keyPem);

            foreach (var tls in new[]
                     {
                         new VaultTlsOptions { ClientCertificatePem = Encoding.UTF8.GetBytes(certificatePem), ClientCertificateKeyPem = Encoding.UTF8.GetBytes(keyPem) },
                         new VaultTlsOptions { ClientCertificateFile = Path.Combine(directory.FullName, "cert.pem"), ClientCertificateKeyFile = Path.Combine(directory.FullName, "key.pem") },
                     })
            {
                var presented = Apply(tls).SslOptions.LocalCertificateSelectionCallback!(this, "vault.test", [], null, []);
                var certificate = Assert.IsType<X509Certificate2>(presented);
                Assert.Equal(leaf.Thumbprint, certificate.Thumbprint);
                Assert.True(certificate.HasPrivateKey);
            }
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void AClientCertificate_NeedsItsKey_AndViceVersa_AndBothMustRead()
    {
        Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions { ClientCertificatePem = [1] }));
        Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions { ClientCertificateKeyFile = "key.pem" }));
        Assert.Throws<ArgumentException>(() => Apply(new VaultTlsOptions { ClientCertificatePem = "junk"u8.ToArray(), ClientCertificateKeyPem = "junk"u8.ToArray() }));
    }

    [Fact]
    public void FromEnvironment_ReadsEveryVariable()
    {
        var variables = new Dictionary<string, string>
        {
            ["VAULT_ADDR"] = "https://from-addr:8200",
            ["VAULT_AGENT_ADDR"] = "https://from-agent:8200",
            ["VAULT_CLIENT_TIMEOUT"] = "1m30s",
            ["VAULT_RATE_LIMIT"] = "10.5:20",
            ["VAULT_DISABLE_REDIRECTS"] = "true",
            ["VAULT_NAMESPACE"] = "ns1",
            ["VAULT_SKIP_VERIFY"] = "T",
            ["VAULT_CACERT"] = "/ca.pem",
            ["VAULT_CACERT_BYTES"] = "pem bytes",
            ["VAULT_CAPATH"] = "/cas",
            ["VAULT_CLIENT_CERT"] = "/cert.pem",
            ["VAULT_CLIENT_KEY"] = "/key.pem",
            ["VAULT_TLS_SERVER_NAME"] = "vault.internal",
            ["VAULT_RETRY_WAIT_MIN"] = "250ms",
            ["VAULT_RETRY_WAIT_MAX"] = "2s",
            ["VAULT_MAX_RETRIES"] = "-1",
        };

        var options = VaultClientOptions.FromEnvironment(name => variables.GetValueOrDefault(name), null);

        Assert.Equal(new Uri("https://from-agent:8200"), options.Address);
        Assert.Equal(TimeSpan.FromSeconds(90), options.RequestTimeout);
        Assert.Equal((10.5, 20), (options.RateLimiter!.RequestsPerSecond, options.RateLimiter.Burst));
        Assert.False(options.FollowRedirects);
        Assert.Equal("ns1", options.Namespace);
        Assert.Null(options.Token);
        Assert.True(options.Tls.InsecureSkipVerify);
        Assert.Equal(("/ca.pem", "pem bytes", "/cas"), (options.Tls.ServerCertificateFile, Encoding.UTF8.GetString(options.Tls.ServerCertificatePem!), options.Tls.ServerCertificateDirectory));
        Assert.Equal(("/cert.pem", "/key.pem", "vault.internal"), (options.Tls.ClientCertificateFile, options.Tls.ClientCertificateKeyFile, options.Tls.ServerName));
        Assert.Equal((TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(2), -1), (options.Retry.RetryWaitMin, options.Retry.RetryWaitMax, options.Retry.RetryMax));
    }

    [Fact]
    public void FromEnvironment_WithNothingSet_IsTheDefaults()
    {
        var options = VaultClientOptions.FromEnvironment(_ => "", null);

        Assert.Equal(new Uri(VaultClientOptions.DefaultAddress), options.Address);
        Assert.Equal(TimeSpan.FromSeconds(60), options.RequestTimeout);
        Assert.Null(options.RateLimiter);
        Assert.True(options.Tls.IsEmpty);
        Assert.Equal(2, options.Retry.RetryMax);
    }

    [Theory]
    [InlineData("10", 10, 10)]
    [InlineData("0.5", 0.5, 1)]
    [InlineData("3:7", 3, 7)]
    public void FromEnvironment_ReadsARateWithOrWithoutABurst(string value, double rate, int burst)
    {
        var limiter = VaultClientOptions.FromEnvironment(name => name == "VAULT_RATE_LIMIT" ? value : null, null).RateLimiter!;

        Assert.Equal((rate, burst), (limiter.RequestsPerSecond, limiter.Burst));
    }

    [Fact]
    public async Task FromEnvironment_ProtectsVaultToken_OnlyGivenAProtector()
    {
        using var t = await TestClient.CreateAsync();
        Func<string, string?> variables = name => name == "VAULT_TOKEN" ? "hvs.from-env" : null;

        var token = Assert.IsType<StaticVaultToken>(VaultClientOptions.FromEnvironment(variables, t.Protector).Token);

        Assert.Equal("hvs.from-env", t.Decrypt(token));
        Assert.Null(VaultClientOptions.FromEnvironment(variables, null).Token);
    }

    [Theory]
    [InlineData("VAULT_ADDR", "not a uri")]
    [InlineData("VAULT_CLIENT_TIMEOUT", "60")]
    [InlineData("VAULT_RATE_LIMIT", "fast")]
    [InlineData("VAULT_RATE_LIMIT", "0")]
    [InlineData("VAULT_RATE_LIMIT", "1:0")]
    [InlineData("VAULT_DISABLE_REDIRECTS", "yes")]
    [InlineData("VAULT_SKIP_VERIFY", "2")]
    [InlineData("VAULT_MAX_RETRIES", "two")]
    [InlineData("VAULT_RETRY_WAIT_MIN", "1x")]
    [InlineData("VAULT_RETRY_WAIT_MAX", "")]
    [InlineData("VAULT_NAMESPACE", "bad\u0001")]
    [InlineData("VAULT_TOKEN", "has space")]
    public async Task FromEnvironment_RefusesAValueThatIsntOne_NamingTheVariable(string name, string value)
    {
        using var t = await TestClient.CreateAsync();

        if (value.Length == 0)
        {
            // Empty is unset, as in vault-client-go.
            VaultClientOptions.FromEnvironment(n => n == name ? value : null, t.Protector);
            return;
        }

        var e = Assert.Throws<FormatException>(() => VaultClientOptions.FromEnvironment(n => n == name ? value : null, t.Protector));
        Assert.Contains(name, e.Message);
    }

    [Fact]
    public void FromEnvironment_DisableRedirectsFalse_LeavesThemAsTheyAre()
        => Assert.False(VaultClientOptions.FromEnvironment(n => n == "VAULT_DISABLE_REDIRECTS" ? "false" : null, null).FollowRedirects);

    private static async Task<HkdfGuard.Abstractions.IDataProtector> ProtectorAsync()
        => (await TestRing.CreateAsync()).CreateProtector(VaultClient.TokenPurpose);

    private static SocketsHttpHandler Apply(VaultTlsOptions tls)
    {
        var handler = new SocketsHttpHandler();
        tls.ApplyTo(handler, supplied: false);
        return handler;
    }

    private static X509Certificate2 CreateCa(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateIntermediate(X509Certificate2 root, string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var certificate = request.Create(root, DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(20), RandomNumberGenerator.GetBytes(8));
        return certificate.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string dnsName) => CreateLeaf(ca, dnsName, out _);

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string dnsName, out ECDsa key)
    {
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dnsName);
        request.CertificateExtensions.Add(names.Build());
        return request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(12), RandomNumberGenerator.GetBytes(8));
    }

    private sealed class PassThrough : DelegatingHandler;
}
