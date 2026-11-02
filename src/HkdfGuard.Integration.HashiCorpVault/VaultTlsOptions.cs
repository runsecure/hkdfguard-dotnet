using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// Which certificates the client - or the HashiCorp Vault transit key wrapper or secret cache -
/// trusts Vault's to be signed by, and which it presents for the cert auth method
/// (https://developer.hashicorp.com/vault/docs/auth/cert) or a Vault requiring mutual TLS. Applied
/// to the SocketsHttpHandler requests go through; all unset, the operating system's trust store
/// decides.
/// <para>
/// Either can instead come from a password-protected PKCS#12 key store: a trust store
/// (<see cref="TrustStoreFile"/>) in place of the PEM CA certificates, a client key store
/// (<see cref="ClientKeyStoreFile"/>) in place of the PEM client certificate and key. A store's
/// password is held only protected, by a protector on the key ring
/// (keyRing.CreateProtector(<see cref="PasswordPurpose"/>), set as <see cref="PasswordProtector"/>):
/// it is decrypted into pinned memory only while the store is read, and zeroed at once.
/// </para>
/// </summary>
public sealed class VaultTlsOptions
{
    /// <summary>
    /// The purpose to create the key store password protector with -
    /// keyRing.CreateProtector(PasswordPurpose) - so a password protected for TLS can't be decrypted
    /// as anything else, nor anything else as it.
    /// </summary>
    public const string PasswordPurpose = "HkdfGuard.Integration.HashiCorpVault.KeyStorePassword";

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

    /// <summary>
    /// A PKCS#12 key store of the CA certificates Vault's certificate must chain to: its certificates
    /// without a private key. Needs <see cref="TrustStorePassword"/>; can't be combined with the PEM CA
    /// certificates.
    /// </summary>
    public string? TrustStoreFile { get; set; }

    /// <summary><see cref="TrustStoreFile"/>'s password, protected by <see cref="PasswordProtector"/> (<see cref="ProtectPassword"/>).</summary>
    public string? TrustStorePassword { get; set; }

    /// <summary>
    /// A PKCS#12 key store holding the client certificate and its private key. Needs
    /// <see cref="ClientKeyStorePassword"/>; can't be combined with the PEM client certificate and key.
    /// </summary>
    public string? ClientKeyStoreFile { get; set; }

    /// <summary><see cref="ClientKeyStoreFile"/>'s password, protected by <see cref="PasswordProtector"/> (<see cref="ProtectPassword"/>).</summary>
    public string? ClientKeyStorePassword { get; set; }

    /// <summary>
    /// The thumbprint (SHA-1, hex) of the certificate <see cref="ClientKeyStoreFile"/> presents; null
    /// when it holds only one with a private key. A thumbprint rather than an alias: .NET doesn't read
    /// PKCS#12 friendly names on every platform.
    /// </summary>
    public string? ClientKeyStoreThumbprint { get; set; }

    /// <summary>Decrypts the key store passwords: a protector on the key ring, keyRing.CreateProtector(<see cref="PasswordPurpose"/>).</summary>
    public IDataProtector? PasswordProtector { get; set; }

    internal bool IsEmpty => ServerCertificateFile is null && ServerCertificatePem is not { Length: > 0 } && ServerCertificateDirectory is null
                             && ClientCertificateFile is null && ClientCertificatePem is not { Length: > 0 }
                             && ClientCertificateKeyFile is null && ClientCertificateKeyPem is not { Length: > 0 }
                             && ServerName is null && !InsecureSkipVerify
                             && TrustStoreFile is null && ClientKeyStoreFile is null;

    /// <summary>
    /// Protects password with passwordProtector - a protector on the key ring,
    /// keyRing.CreateProtector(<see cref="PasswordPurpose"/>) - for <see cref="TrustStorePassword"/>
    /// or <see cref="ClientKeyStorePassword"/>. password is read, never kept or cleared: zero it once
    /// this returns.
    /// </summary>
    /// <exception cref="ArgumentNullException">passwordProtector is null</exception>
    /// <exception cref="ArgumentException">password is empty</exception>
    public static string ProtectPassword(IDataProtector passwordProtector, ReadOnlySpan<char> password)
    {
        ArgumentNullException.ThrowIfNull(passwordProtector);
        if (password.IsEmpty)
            throw new ArgumentException("A key store password can't be empty.", nameof(password));

        return passwordProtector.Encrypt(password);
    }

    internal VaultTlsOptions Clone() => (VaultTlsOptions)MemberwiseClone();

    /// <summary>Configures handler's TLS from these options.</summary>
    /// <exception cref="ArgumentException">A certificate, key or key store can't be read; a client
    /// certificate has no key or a key no certificate; a key store has no password, or one
    /// PasswordProtector didn't protect; or a key store is combined with the PEM it replaces</exception>
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
        if (TrustStoreFile is not null)
        {
            if (ServerCertificateFile is not null || ServerCertificatePem is { Length: > 0 } || ServerCertificateDirectory is not null)
                throw new ArgumentException("A trust store and PEM CA certificates can't be given together.");
            return TrustStoreCertificates(TrustStoreFile);
        }

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

    // The trust store's certificates without a private key.
    private X509Certificate2Collection TrustStoreCertificates(string file)
    {
        var loaded = LoadKeyStore(file, TrustStorePassword, "trust store");
        var roots = new X509Certificate2Collection();
        foreach (var certificate in loaded)
        {
            if (certificate.HasPrivateKey)
                certificate.Dispose();
            else
                roots.Add(certificate);
        }

        if (roots.Count == 0)
            throw new ArgumentException($"The trust store {file} holds no trusted certificate.");
        return roots;
    }

    // The client key store's certificate with a private key: the one ClientKeyStoreThumbprint names,
    // or its only one.
    private X509Certificate2 ClientCertificateFromStore(string file)
    {
        var loaded = LoadKeyStore(file, ClientKeyStorePassword, "client key store");
        X509Certificate2? chosen = null;
        try
        {
            foreach (var certificate in loaded)
            {
                if (!certificate.HasPrivateKey)
                    continue;
                if (ClientKeyStoreThumbprint is { } thumbprint)
                {
                    if (string.Equals(certificate.Thumbprint, thumbprint.Replace(" ", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase))
                        chosen = certificate;
                    continue;
                }

                if (chosen is not null)
                    throw new ArgumentException(
                        $"The client key store {file} holds more than one private key: name the certificate to present with ClientKeyStoreThumbprint.");
                chosen = certificate;
            }

            return chosen ?? throw new ArgumentException(ClientKeyStoreThumbprint is null
                ? $"The client key store {file} holds no private key."
                : $"The client key store {file} holds no private key for the certificate {ClientKeyStoreThumbprint}.");
        }
        finally
        {
            foreach (var certificate in loaded)
            {
                if (!ReferenceEquals(certificate, chosen))
                    certificate.Dispose();
            }
        }
    }

    // Reads the PKCS#12 file, unlocked with the password protectedPassword holds: decrypted into
    // pinned memory only for that, and zeroed once it has been read.
    private X509Certificate2Collection LoadKeyStore(string file, string? protectedPassword, string what)
    {
        if (string.IsNullOrEmpty(protectedPassword))
            throw new ArgumentException($"The {what} {file} needs its password, protected: VaultTlsOptions.ProtectPassword.");
        if (PasswordProtector is null)
            throw new ArgumentException($"The {what}'s password needs the protector that protected it: set PasswordProtector.");

        var password = DecryptPassword(PasswordProtector, protectedPassword, what, out var length);
        try
        {
            return X509CertificateLoader.LoadPkcs12CollectionFromFile(file, password.AsSpan(0, length));
        }
        catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException)
        {
            // A wrong password is reported as a CryptographicException.
            throw new ArgumentException($"Could not read the {what} {file}: {e.Message}", e);
        }
        finally
        {
            ArrayUtility.ZeroMemory(password.AsSpan());
        }
    }

    // The password protectedPassword holds, in a pinned array the caller zeroes; its first length
    // characters are the password. The protector's exceptions aren't chained: a parser handed an
    // unprotected password could quote it.
    private static char[] DecryptPassword(IDataProtector protector, string protectedPassword, string what, out int length)
    {
        int maxLength;
        try
        {
            maxLength = protector.GetMaxDecryptedLength(protectedPassword);
        }
        catch (FormatException)
        {
            throw NotProtected(what);
        }

        var chars = ArrayUtility.AllocatePinned<char>(maxLength);
        try
        {
            length = protector.Decrypt(protectedPassword, chars);
            return chars;
        }
        catch (Exception e) when (e is FormatException or CryptographicException or KeyNotFoundException)
        {
            ArrayUtility.ZeroMemory(chars.AsSpan());
            throw NotProtected(what);
        }
    }

    private static ArgumentException NotProtected(string what)
        => new($"The {what}'s password isn't protected by PasswordProtector: give VaultTlsOptions.ProtectPassword(PasswordProtector, password), never the password itself.");

    private X509Certificate2? ClientCertificate()
    {
        var hasCertificate = ClientCertificateFile is not null || ClientCertificatePem is { Length: > 0 };
        var hasKey = ClientCertificateKeyFile is not null || ClientCertificateKeyPem is { Length: > 0 };
        if (ClientKeyStoreFile is not null)
        {
            if (hasCertificate || hasKey)
                throw new ArgumentException("A client key store and a PEM client certificate or key can't be given together.");
            return ClientCertificateFromStore(ClientKeyStoreFile);
        }

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
