using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace HkdfGuard.Options.Certificate;

/// <summary>
/// Validates a <see cref="CertificateOptions"/> instance before anything is opened: exactly one
/// source set, and one this operating system has - the Windows store on Windows, a keychain on
/// macOS, an OpenSSL provider on Linux, a file anywhere - with a store, subject, provider, key or
/// path that is one. A file holding a private key must be protected by a password, named by its
/// secret, unless an unprotected key is explicitly allowed.
/// </summary>
public sealed class CertificateOptionsValidator : IValidateOptions<CertificateOptions>
{
    private readonly OSPlatform _platform;

    /// <summary>A validator for the operating system the process runs on.</summary>
    public CertificateOptionsValidator()
        : this(PlatformOf(OperatingSystem.IsWindows(), OperatingSystem.IsMacOS(), OperatingSystem.IsLinux()))
    {
    }

    /// <summary>A validator for <paramref name="platform"/>, for tests.</summary>
    internal CertificateOptionsValidator(OSPlatform platform) => _platform = platform;

    public ValidateOptionsResult Validate(string? name, CertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var failures = new List<string>();

        var sources = new (string Name, object? Value, OSPlatform? Platform)[]
        {
            (nameof(CertificateOptions.Windows), options.Windows, OSPlatform.Windows),
            (nameof(CertificateOptions.MacOS), options.MacOS, OSPlatform.OSX),
            (nameof(CertificateOptions.Linux), options.Linux, OSPlatform.Linux),
            (nameof(CertificateOptions.File), options.File, null),
        };
        var set = sources.Where(s => s.Value is not null).ToList();

        if (set.Count == 0)
            failures.Add("One certificate source is required: Windows, MacOS, Linux or File.");
        else if (set.Count > 1)
            failures.Add($"Only one certificate source can be set, but {string.Join(", ", set.Select(s => s.Name))} are.");

        foreach (var source in set)
        {
            if (source.Platform is { } platform && platform != _platform)
                failures.Add($"The {source.Name} certificate source can only be used on {source.Name}; this is {Describe(_platform)}.");
        }

        var pinned = options.Thumbprint is not null;
        if (pinned && Thumbprints.Normalize(options.Thumbprint) is null)
            failures.Add($"Thumbprint must be a certificate's SHA-1 (40 hex digits) or SHA-256 (64 hex digits) thumbprint, not '{options.Thumbprint}'.");

        if (options.Windows is { } windows)
            ValidateStore(nameof(CertificateOptions.Windows), windows, pinned, failures);
        if (options.MacOS is { } macOS)
            ValidateStore(nameof(CertificateOptions.MacOS), macOS, pinned, failures);
        if (options.Linux is { } linux)
            ValidateLinux(linux, options.RequirePrivateKey, failures);
        if (options.File is { } file)
            ValidateFile(file, options.RequirePrivateKey, failures);

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateStore(string source, CertificateStoreOptions store, bool pinned, List<string> failures)
    {
        if (!Enum.IsDefined(store.StoreLocation))
            failures.Add($"{source}.StoreLocation must be CurrentUser or LocalMachine, not {store.StoreLocation}.");
        if (!Enum.IsDefined(store.StoreName))
            failures.Add($"{source}.StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not {store.StoreName}.");

        if (store.Subject is null && pinned)
            return;
        if (string.IsNullOrWhiteSpace(store.Subject))
        {
            failures.Add($"{source}.Subject is required unless Thumbprint is set: the certificate's subject distinguished name, e.g. \"CN=api.example.com\".");
            return;
        }

        try
        {
            _ = new X500DistinguishedName(store.Subject);
        }
        catch (CryptographicException)
        {
            failures.Add($"{source}.Subject must be a distinguished name, e.g. \"CN=api.example.com, O=Contoso\", not '{store.Subject}'.");
        }
    }

    private static void ValidateLinux(LinuxOpenSslProviderOptions linux, bool requirePrivateKey, List<string> failures)
    {
        if (string.IsNullOrEmpty(linux.Provider) || !linux.Provider.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            failures.Add($"Linux.Provider must be an OpenSSL provider's name - \"tpm2\" or \"pkcs11\" - not '{linux.Provider}'.");
        if (requirePrivateKey && string.IsNullOrWhiteSpace(linux.KeyUri))
            failures.Add("Linux.KeyUri is required: the key as the provider names it, e.g. \"handle:0x81000001\".");
        ValidatePath("Linux.CertificateFile", linux.CertificateFile, failures);
    }

    private static void ValidateFile(CertificateFileOptions file, bool requirePrivateKey, List<string> failures)
    {
        ValidatePath("File.Path", file.Path, failures);

        if (!Enum.IsDefined(file.Format))
            failures.Add($"File.Format must be Pkcs12 or Pem, not {file.Format}.");
        else if (file.Format == CertificateFileFormat.Pem && requirePrivateKey)
            ValidatePath("File.KeyPath", file.KeyPath, failures);

        if (file.PasswordSecretName is not null && string.IsNullOrWhiteSpace(file.PasswordSecretName))
            failures.Add("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset.");
        else if (requirePrivateKey && file.PasswordSecretName is null && !file.AllowUnprotectedPrivateKey)
            failures.Add("File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. "
                         + "Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.");
    }

    private static void ValidatePath(string what, string? path, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(path))
            failures.Add($"{what} is required.");
        else if (!System.IO.Path.IsPathFullyQualified(path))
            failures.Add($"{what} must be an absolute path, not '{path}'.");
    }

    // The platform an OS is, from OperatingSystem's checks; anything else is treated as FreeBSD,
    // which no native source is for.
    internal static OSPlatform PlatformOf(bool isWindows, bool isMacOS, bool isLinux)
        => isWindows ? OSPlatform.Windows
            : isMacOS ? OSPlatform.OSX
            : isLinux ? OSPlatform.Linux
            : OSPlatform.FreeBSD;

    private static string Describe(OSPlatform platform)
        => platform == OSPlatform.Windows ? "Windows"
            : platform == OSPlatform.OSX ? "macOS"
            : platform == OSPlatform.Linux ? "Linux"
            : platform.ToString();
}
