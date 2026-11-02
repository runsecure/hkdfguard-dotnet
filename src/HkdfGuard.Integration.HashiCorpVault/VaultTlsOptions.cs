using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// Which certificates the client trusts Vault's to be signed by, and which it presents for the cert
/// auth method (https://developer.hashicorp.com/vault/docs/auth/cert). Applied to the client's
/// SocketsHttpHandler; all unset, the operating system's trust store decides.
/// </summary>
public sealed class VaultTlsOptions
{
    /// <summary>A PEM file of the CA certificate(s) Vault's certificate must chain to - VAULT_CACERT. Takes precedence over <see cref="ServerCertificatePem"/> and <see cref="ServerCertificateDirectory"/>.</summary>
    public string? ServerCertificateFile { get; set; }

    /// <summary>PEM-encoded CA certificate(s) - VAULT_CACERT_BYTES. Takes precedence over <see cref="ServerCertificateDirectory"/>.</summary>
    public byte[]? ServerCertificatePem { get; set; }

    /// <summary>A directory of PEM-encoded CA certificates - VAULT_CAPATH. Every file in it must hold at least one.</summary>
    public string? ServerCertificateDirectory { get; set; }

    /// <summary>A PEM file of the client certificate - VAULT_CLIENT_CERT. Takes precedence over <see cref="ClientCertificatePem"/>; needs a key.</summary>
    public string? ClientCertificateFile { get; set; }

    /// <summary>The PEM-encoded client certificate; needs a key.</summary>
    public byte[]? ClientCertificatePem { get; set; }

    /// <summary>A PEM file of the client certificate's private key - VAULT_CLIENT_KEY. Takes precedence over <see cref="ClientCertificateKeyPem"/>.</summary>
    public string? ClientCertificateKeyFile { get; set; }

    /// <summary>The client certificate's PEM-encoded private key.</summary>
    public byte[]? ClientCertificateKeyPem { get; set; }

    /// <summary>
    /// The name Vault's certificate must be issued to, when it isn't the address's host (connecting
    /// by IP, say) - VAULT_TLS_SERVER_NAME. Only verification uses it: the TLS handshake still names
    /// the address's host.
    /// </summary>
    public string? ServerName { get; set; }

    /// <summary>
    /// Accepts any certificate Vault presents - VAULT_SKIP_VERIFY. Anyone between the client and Vault
    /// can then read every token and secret: for a throwaway dev server only.
    /// </summary>
    public bool InsecureSkipVerify { get; set; }

    internal bool IsEmpty => ServerCertificateFile is null && ServerCertificatePem is not { Length: > 0 } && ServerCertificateDirectory is null
                             && ClientCertificateFile is null && ClientCertificatePem is not { Length: > 0 }
                             && ClientCertificateKeyFile is null && ClientCertificateKeyPem is not { Length: > 0 }
                             && ServerName is null && !InsecureSkipVerify;

    internal VaultTlsOptions Clone() => (VaultTlsOptions)MemberwiseClone();

    /// <summary>Configures handler's TLS from these options.</summary>
    /// <exception cref="ArgumentException">A certificate can't be read, or a client certificate has no key or a key no certificate</exception>
    internal void ApplyTo(SocketsHttpHandler handler)
    {
        var roots = ServerCertificates();
        var serverName = ServerName;
        if (InsecureSkipVerify)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        else if (roots is not null || serverName is not null)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                IsTrusted(certificate, chain, errors, roots, serverName);

        if (ClientCertificate() is { } client)
        {
            // Presented whatever CAs Vault says it accepts, as vault-client-go does: the cert auth
            // method's CAs needn't be in the server's own list.
            handler.SslOptions.LocalCertificateSelectionCallback = (_, _, _, _, _) => client;
        }
    }

    // Vault's certificate chains to roots (or the system's trust, without roots) and is issued to
    // serverName (or the address's host, without one).
    private static bool IsTrusted(X509Certificate? certificate, X509Chain? systemChain, SslPolicyErrors errors,
        X509Certificate2Collection? roots, string? serverName)
    {
        if (certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
            return false;

        using var presented = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        if (serverName is not null ? !presented.MatchesHostname(serverName) : errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
            return false;

        if (roots is null)
            return !errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        // Intermediates Vault sent along.
        if (systemChain is not null)
        {
            foreach (var element in systemChain.ChainElements)
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(presented);
    }

    private X509Certificate2Collection? ServerCertificates()
    {
        var roots = new X509Certificate2Collection();
        if (ServerCertificateFile is not null)
            Import(roots, File.ReadAllText(ServerCertificateFile), ServerCertificateFile);
        else if (ServerCertificatePem is { Length: > 0 } pem)
            Import(roots, System.Text.Encoding.UTF8.GetString(pem), nameof(ServerCertificatePem));
        else if (ServerCertificateDirectory is not null)
        {
            foreach (var file in Directory.EnumerateFiles(ServerCertificateDirectory).Order(StringComparer.Ordinal))
                Import(roots, File.ReadAllText(file), file);
        }
        else
            return null;

        return roots;
    }

    private static void Import(X509Certificate2Collection roots, string pem, string source)
    {
        var before = roots.Count;
        try
        {
            roots.ImportFromPem(pem);
        }
        catch (System.Security.Cryptography.CryptographicException e)
        {
            throw new ArgumentException($"Could not read the CA certificate(s) in {source}: {e.Message}", e);
        }

        if (roots.Count == before)
            throw new ArgumentException($"{source} holds no PEM-encoded certificate.");
    }

    private X509Certificate2? ClientCertificate()
    {
        var hasCertificate = ClientCertificateFile is not null || ClientCertificatePem is { Length: > 0 };
        var hasKey = ClientCertificateKeyFile is not null || ClientCertificateKeyPem is { Length: > 0 };
        if (hasCertificate != hasKey)
            throw new ArgumentException("A client certificate and its key must be given together.");
        if (!hasCertificate)
            return null;

        var certificate = ClientCertificateFile is not null ? File.ReadAllText(ClientCertificateFile) : System.Text.Encoding.UTF8.GetString(ClientCertificatePem!);
        var key = ClientCertificateKeyFile is not null ? File.ReadAllText(ClientCertificateKeyFile) : System.Text.Encoding.UTF8.GetString(ClientCertificateKeyPem!);
        try
        {
            using var pair = X509Certificate2.CreateFromPem(certificate, key);
            // Windows' TLS can't use the ephemeral key CreateFromPem gives the certificate: round-trip
            // it through PKCS#12 so the key is one SChannel can sign with.
            return X509CertificateLoader.LoadPkcs12(pair.Export(X509ContentType.Pkcs12), null);
        }
        catch (System.Security.Cryptography.CryptographicException e)
        {
            throw new ArgumentException($"Could not read the client certificate and key: {e.Message}", e);
        }
    }
}
