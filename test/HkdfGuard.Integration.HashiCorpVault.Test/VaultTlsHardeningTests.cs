using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// How the client secures its connection beyond the defaults: a custom CA only vouches for TLS
/// server certificates, a supplied handler is never reconfigured behind its owner's back, skipping
/// verification is always logged, and a handler whose redirect behaviour can't be read is refused.
/// </summary>
public class VaultTlsHardeningTests
{
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    private static async Task<HkdfGuard.Abstractions.IDataProtector> ProtectorAsync()
        => (await TestRing.CreateAsync()).CreateProtector(VaultClient.TokenPurpose);

    [Theory]
    [InlineData(null, true)] // no EKU extension: valid for every purpose, as RFC 5280 says
    [InlineData(ServerAuth, true)]
    [InlineData(ClientAuth, false)]
    public void ACustomCa_VouchesOnlyForCertificatesIssuedForTlsServers(string? eku, bool trusted)
    {
        using var ca = CreateCa();
        using var leaf = CreateLeaf(ca, "vault.test", eku);
        var handler = new SocketsHttpHandler();
        new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(ca.ExportCertificatePem()) }.ApplyTo(handler, supplied: false);

        Assert.Equal(trusted, handler.SslOptions.RemoteCertificateValidationCallback!(this, leaf, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public async Task InsecureSkipVerify_IsRefusedForASuppliedHandler_AndLeavesItUntouched()
    {
        var supplied = new SocketsHttpHandler { AllowAutoRedirect = false };
        var protector = await ProtectorAsync();

        var ex = Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions
        {
            HttpMessageHandler = supplied,
            Tls = new VaultTlsOptions { InsecureSkipVerify = true },
        }));

        Assert.Contains("InsecureSkipVerify", ex.Message);
        Assert.Null(supplied.SslOptions.RemoteCertificateValidationCallback);
        Assert.Throws<ArgumentException>(() => VaultHttp.CreateHttpClient(null, supplied, new VaultTlsOptions { InsecureSkipVerify = true }));
    }

    [Fact]
    public async Task InsecureSkipVerify_OnTheClientsOwnHandler_IsLoggedAsAWarning()
    {
        var logger = new ListLogger();

        using var client = new VaultClient(await ProtectorAsync(),
            new VaultClientOptions { Tls = new VaultTlsOptions { InsecureSkipVerify = true } }, logger);
        using var http = VaultHttp.CreateHttpClient(null, null, new VaultTlsOptions { InsecureSkipVerify = true }, logger);

        Assert.Equal(2, logger.Entries.Count(e => e.Level == LogLevel.Warning && e.Message.Contains("not being verified", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ASuppliedHandlersOwnValidationCallback_IsNeverReplaced()
    {
        using var ca = CreateCa();
        RemoteCertificateValidationCallback owners = (_, _, _, _) => false;
        var supplied = new SocketsHttpHandler { AllowAutoRedirect = false, SslOptions = { RemoteCertificateValidationCallback = owners } };
        var tls = new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(ca.ExportCertificatePem()) };

        var protector = await ProtectorAsync();
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = supplied, Tls = tls }));
        Assert.Throws<ArgumentException>(() => VaultHttp.CreateHttpClient(null, supplied, tls));

        Assert.Same(owners, supplied.SslOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    public async Task TwoClientsSharingOneSuppliedHandler_TheSecondIsRefused()
    {
        using var ca = CreateCa();
        using var otherCa = CreateCa();
        var supplied = new SocketsHttpHandler { AllowAutoRedirect = false };
        var protector = await ProtectorAsync();

        using var first = new VaultClient(protector, new VaultClientOptions
        {
            HttpMessageHandler = supplied,
            Tls = new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(ca.ExportCertificatePem()) },
        });
        var configured = supplied.SslOptions.RemoteCertificateValidationCallback;
        Assert.NotNull(configured);

        // A second client trusting another CA would otherwise silently change what the first trusts.
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions
        {
            HttpMessageHandler = supplied,
            Tls = new VaultTlsOptions { ServerCertificatePem = Encoding.UTF8.GetBytes(otherCa.ExportCertificatePem()) },
        }));
        Assert.Same(configured, supplied.SslOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    public async Task ASuppliedHandlersOwnClientCertificateAndConnectCallbacks_AreNeverReplaced()
    {
        using var ca = CreateCa();
        using var leaf = CreateLeaf(ca, "client", eku: null, out var key);
        var tls = new VaultTlsOptions
        {
            ClientCertificatePem = Encoding.UTF8.GetBytes(leaf.ExportCertificatePem()),
            ClientCertificateKeyPem = Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()),
        };
        LocalCertificateSelectionCallback select = (_, _, _, _, _) => null!;
        var withSelection = new SocketsHttpHandler { AllowAutoRedirect = false, SslOptions = { LocalCertificateSelectionCallback = select } };
        Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> connect = (_, _) => throw new NotSupportedException();
        var withConnect = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectCallback = connect };
        var protector = await ProtectorAsync();

        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = withSelection, Tls = tls }));
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions
        {
            HttpMessageHandler = withConnect,
            Address = new Uri("unix:///var/run/vault.sock"),
        }));

        Assert.Same(select, withSelection.SslOptions.LocalCertificateSelectionCallback);
        Assert.Same(connect, withConnect.ConnectCallback);
    }

    [Fact]
    public async Task AClientCertificateFromPem_IsStillPresented_WithItsKey()
    {
        using var ca = CreateCa();
        using var leaf = CreateLeaf(ca, "client", eku: ClientAuth, out var key);
        var handler = new SocketsHttpHandler();
        new VaultTlsOptions
        {
            ClientCertificatePem = Encoding.UTF8.GetBytes(leaf.ExportCertificatePem()),
            ClientCertificateKeyPem = Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()),
        }.ApplyTo(handler, supplied: false);

        var presented = Assert.IsType<X509Certificate2>(handler.SslOptions.LocalCertificateSelectionCallback!(this, "vault.test", [], null, []));
        Assert.Equal(leaf.Thumbprint, presented.Thumbprint);
        Assert.True(presented.HasPrivateKey);
        using var signer = presented.GetECDsaPrivateKey()!;
        Assert.True(key.VerifyData("probe"u8, signer.SignData("probe"u8, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256));
        await Task.CompletedTask;
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void AnUnknownHandler_IsAskedThroughItsOwnRedirectProperty(bool automaticRedirection, bool follows)
        => Assert.Equal(follows, VaultHttp.FollowsRedirects(new WinHttpLikeHandler { AutomaticRedirection = automaticRedirection }));

    [Fact]
    public async Task AnUnknownHandlerWithNoRedirectProperty_CountsAsFollowingRedirects_AndIsRefused()
    {
        var opaque = new PassThrough { InnerHandler = new OpaqueHandler() };

        Assert.True(VaultHttp.FollowsRedirects(opaque));
        Assert.Throws<ArgumentException>(() => VaultHttp.CheckRedirects(opaque, allowRedirects: false, "options"));
        VaultHttp.CheckRedirects(opaque, allowRedirects: true, "options");
        var protector = await ProtectorAsync();
        Assert.Throws<ArgumentException>(() => new VaultClient(protector, new VaultClientOptions { HttpMessageHandler = opaque }));
    }

    private static X509Certificate2 CreateCa()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN=Test CA {Guid.NewGuid():N}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string dnsName, string? eku) => CreateLeaf(ca, dnsName, eku, out _);

    private static X509Certificate2 CreateLeaf(X509Certificate2 ca, string dnsName, string? eku, out ECDsa key)
    {
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(dnsName);
        request.CertificateExtensions.Add(names.Build());
        if (eku is not null)
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(eku)], false));
        return request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(12), RandomNumberGenerator.GetBytes(8));
    }

    private sealed class PassThrough : DelegatingHandler;

    // Like WinHttpHandler: not a SocketsHttpHandler, with its own redirect switch.
    private sealed class WinHttpLikeHandler : HttpMessageHandler
    {
        public bool AutomaticRedirection { get; set; } = true;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    // A handler whose redirect behaviour can't be read at all.
    private sealed class OpaqueHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class ListLogger : ILogger<VaultClient>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }
}
