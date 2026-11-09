using System.Security.Cryptography.X509Certificates;

namespace HkdfGuard.Options.Certificate;

/// <summary>
/// Plain-data description of where one X509Certificate2 - with its private key - is opened from:
/// exactly one of the operating system's own protected key storage (<see cref="Windows"/>,
/// <see cref="MacOS"/>, <see cref="Linux"/>) or a key file on the filesystem (<see cref="File"/>).
/// It carries no behavior and never a password: a file's password is named here, and read at load
/// time from a protected secret source, so it is never plaintext on disk or in configuration.
/// Validate it with <see cref="CertificateOptionsValidator"/>; for several certificates, bind one
/// instance per name (named options).
/// <code>
/// "Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
/// "Certificate": { "Thumbprint": "3A1F...C9", "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My" } }
/// "Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
/// "Certificate": { "Linux": { "Provider": "tpm2", "KeyUri": "handle:0x81000001", "CertificateFile": "/etc/myapp/tls.crt" } }
/// "Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
/// </code>
/// </summary>
public sealed class CertificateOptions
{
    /// <summary>A certificate in a Windows certificate store, its key held by CNG.</summary>
    public CertificateStoreOptions? Windows { get; set; }

    /// <summary>A certificate in a macOS keychain, its key held by the keychain.</summary>
    public CertificateStoreOptions? MacOS { get; set; }

    /// <summary>A certificate whose key is opened through an OpenSSL 3 provider on Linux - the TPM, say.</summary>
    public LinuxOpenSslProviderOptions? Linux { get; set; }

    /// <summary>A certificate and key read from files, the key protected by a password.</summary>
    public CertificateFileOptions? File { get; set; }

    /// <summary>
    /// Whether the certificate must come with its private key: true (the default) for one presented
    /// as a TLS server or client certificate, or used to sign; false for one only to be trusted.
    /// </summary>
    public bool RequirePrivateKey { get; set; } = true;

    /// <summary>
    /// Pins the one certificate to open, by its thumbprint: the SHA-1 (40 hex digits, as Windows and
    /// macOS show it) or SHA-256 (64 hex digits) hash of the certificate. Spaces, colons and the
    /// invisible marks Windows' certificate dialog copies along are ignored, and so is case.
    /// <para>
    /// From a store, only the certificate with this thumbprint is chosen - and with
    /// <see cref="CertificateStoreOptions.Subject"/> set too, it must have that subject as well - so
    /// another certificate added to the store under the same subject, by whoever can write to it, is
    /// never picked. The price is renewal: a renewed certificate has a new thumbprint, so this must
    /// be changed with it. From a file or a Linux certificate file, the certificate read must have
    /// this thumbprint, so a replaced file is refused. Null (the default) pins nothing.
    /// </para>
    /// </summary>
    public string? Thumbprint { get; set; }
}

/// <summary>
/// A certificate in an operating system certificate store, found by its subject, its thumbprint
/// (<see cref="CertificateOptions.Thumbprint"/>), or both. By subject alone, a renewed certificate an
/// administrator adds under the same subject is picked up with no change to configuration. Of the
/// certificates that match, the one opened is the one valid now - and with its private key, when one
/// is required - that expires last; an expired or not-yet-valid one is never chosen. Its private key
/// stays in the store: CNG (or the TPM) on Windows, the keychain on macOS, where CurrentUser is the
/// login keychain and LocalMachine the System keychain.
/// <para>
/// Matching by subject alone trusts whoever can add a certificate to the store to choose it - add one
/// with the same subject, a later expiry and their own key, and it is the one opened. Keep it to a
/// store only administrators can write, such as LocalMachine's My, or pin the certificate by
/// <see cref="CertificateOptions.Thumbprint"/>, which no other certificate can match.
/// </para>
/// </summary>
public sealed class CertificateStoreOptions
{
    /// <summary>Which store location to open. Default <see cref="StoreLocation.LocalMachine"/>.</summary>
    public StoreLocation StoreLocation { get; set; } = StoreLocation.LocalMachine;

    /// <summary>Which store to open. Default <see cref="StoreName.My"/> (Personal).</summary>
    public StoreName StoreName { get; set; } = StoreName.My;

    /// <summary>
    /// The certificate's subject distinguished name, as the certificate states it:
    /// "CN=api.example.com, O=Contoso". Compared to each certificate's whole subject, ignoring case -
    /// never as a substring, so "CN=api" doesn't match "CN=api.example.com". Required unless
    /// <see cref="CertificateOptions.Thumbprint"/> is set.
    /// </summary>
    public string? Subject { get; set; }
}

/// <summary>
/// A certificate on Linux whose private key is opened through an OpenSSL 3 provider - tpm2 for a
/// key in the TPM, or pkcs11 for a hardware token - so the key never leaves it, beside the
/// certificate itself as a PEM file, which holds nothing secret. .NET's own X509Store isn't used on
/// Linux: it is a folder of unprotected key files.
/// </summary>
public sealed class LinuxOpenSslProviderOptions
{
    /// <summary>The OpenSSL provider that holds the key: "tpm2" (the default) or "pkcs11".</summary>
    public string Provider { get; set; } = "tpm2";

    /// <summary>
    /// The key, as the provider names it: "handle:0x81000001" for a persistent TPM key, a path to a
    /// TPM key blob, or a "pkcs11:" URI.
    /// </summary>
    public string? KeyUri { get; set; }

    /// <summary>The certificate, PEM-encoded, without its key; absolute.</summary>
    public string? CertificateFile { get; set; }
}

/// <summary>The format of a certificate file.</summary>
public enum CertificateFileFormat
{
    /// <summary>A PKCS#12 (.pfx/.p12) file holding the certificate and its key.</summary>
    Pkcs12,

    /// <summary>A PEM certificate, with its key in <see cref="CertificateFileOptions.KeyPath"/> as encrypted PKCS#8.</summary>
    Pem,
}

/// <summary>
/// A certificate and its key read from files, absolute paths. The key must be protected by a
/// password - a password-protected PKCS#12 file, or an encrypted PKCS#8 PEM key - and the password
/// comes from the secret <see cref="PasswordSecretName"/> names, never from configuration. An
/// unprotected key file is refused unless <see cref="AllowUnprotectedPrivateKey"/> is set.
/// <para>
/// Each file is read as every other secret file is (TrustedFile): refused unless only the operating
/// system's administrators, and the principals the loader is given to trust, could have written or
/// replaced it and every folder above it - so nobody else can swap in their own certificate and key.
/// Its contents are read into pinned memory, zeroed once parsed.
/// </para>
/// </summary>
public sealed class CertificateFileOptions
{
    /// <summary>The certificate file - PKCS#12, or a PEM certificate.</summary>
    public string? Path { get; set; }

    /// <summary>The file's format. Default <see cref="CertificateFileFormat.Pkcs12"/>.</summary>
    public CertificateFileFormat Format { get; set; } = CertificateFileFormat.Pkcs12;

    /// <summary>The PEM private key file, for <see cref="CertificateFileFormat.Pem"/>; ignored for PKCS#12.</summary>
    public string? KeyPath { get; set; }

    /// <summary>
    /// The name of the secret holding the key's password, as a protected secret source - a
    /// FilePerSecretCache, a remote secret cache, protected configuration - is asked for it. The
    /// password is decrypted only while the key is read, into memory zeroed straight after.
    /// </summary>
    public string? PasswordSecretName { get; set; }

    /// <summary>
    /// Accepts a key file with no password - a PKCS#12 file without one, or a plain PEM key - whose
    /// private key is then plaintext on disk, protected only by file permissions. Default false;
    /// set it only for development.
    /// </summary>
    public bool AllowUnprotectedPrivateKey { get; set; }
}
