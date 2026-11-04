using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HkdfGuard.Abstractions;
using Microsoft.Extensions.Options;

namespace HkdfGuard.Options.Certificate;

/// <summary>
/// Opens the X509Certificate2 a validated <see cref="CertificateOptions"/> describes. The caller owns
/// what it returns, and disposes it.
/// <list type="bullet">
/// <item>A store (<see cref="CertificateOptions.Windows"/>, <see cref="CertificateOptions.MacOS"/>)
/// is opened read-only, and of the certificates whose subject is the one named, the one valid now -
/// with its private key, when one is required - that expires last is returned; every other is
/// disposed. The key stays where the store keeps it.</item>
/// <item>A Linux OpenSSL provider key (<see cref="CertificateOptions.Linux"/>) is opened by its URI
/// and attached to the PEM certificate, so every use of the key goes through the provider - the TPM,
/// say - and the key itself is never in the process.</item>
/// <item>A file (<see cref="CertificateOptions.File"/>) is read with its password, which is
/// decrypted from the password source into pinned memory only while the key is read, and zeroed at
/// once; it is never a string. A PKCS#12 key is imported non-exportable and not persisted. On
/// Windows a PEM key, which .NET imports as an ephemeral key that SChannel can't use as a TLS
/// server's, is moved into the same kind of key by an export, zeroed at once, and an import.</item>
/// </list>
/// Whatever the source, a certificate that isn't valid now, or that has no private key when one is
/// required, is refused.
/// </summary>
public sealed class CertificateOptionsLoader
{
    // Not Exportable, so the key can't be exported again; not PersistKeySet, so on Windows the key
    // the import writes is deleted when the certificate is disposed.
    private const X509KeyStorageFlags KeyStorage = X509KeyStorageFlags.DefaultKeySet;

    private const string RsaAlgorithm = "1.2.840.113549.1.1.1";
    private const string EcAlgorithm = "1.2.840.10045.2.1";

    private readonly IProtectedReadOnlyCache? _passwords;
    private readonly TimeProvider _time;
    private readonly IValidateOptions<CertificateOptions> _validator;
    private readonly Func<StoreName, StoreLocation, X509Certificate2Collection> _openStore;

    // Whether a PEM key is moved out of the ephemeral key .NET imports it as: on Windows only.
    private readonly bool _reimportPemKeys;

    /// <param name="passwords">Where a file's password is read from, by
    /// <see cref="CertificateFileOptions.PasswordSecretName"/> - a FilePerSecretCache, a remote secret
    /// cache, protected configuration. Needed only for a file with a password.</param>
    /// <param name="timeProvider">The clock a certificate's validity is judged by; null for the system's.</param>
    public CertificateOptionsLoader(IProtectedReadOnlyCache? passwords = null, TimeProvider? timeProvider = null)
        : this(passwords, timeProvider, new CertificateOptionsValidator(), ReadStore, OperatingSystem.IsWindows())
    {
    }

    /// <summary>A loader with its validator, store reader and platform behavior given, for tests.</summary>
    internal CertificateOptionsLoader(IProtectedReadOnlyCache? passwords, TimeProvider? timeProvider,
        IValidateOptions<CertificateOptions> validator, Func<StoreName, StoreLocation, X509Certificate2Collection> openStore,
        bool reimportPemKeys)
    {
        _passwords = passwords;
        _time = timeProvider ?? TimeProvider.System;
        _validator = validator;
        _openStore = openStore;
        _reimportPemKeys = reimportPemKeys;
    }

    /// <summary>
    /// Opens the certificate options describes, reading a file's password synchronously - blocking,
    /// for a remote password source, until it answers.
    /// </summary>
    /// <param name="options">What to open</param>
    /// <param name="name">The options' name, for named options; it is only reported in a validation failure.</param>
    /// <exception cref="ArgumentNullException">options is null</exception>
    /// <exception cref="OptionsValidationException">The options aren't valid on this operating system</exception>
    /// <exception cref="InvalidOperationException">No certificate valid now (with its private key, when
    /// required) was found, or a password is needed and the loader has no password source</exception>
    /// <exception cref="KeyNotFoundException">The password source holds no secret by the name given</exception>
    /// <exception cref="CryptographicException">A file isn't a certificate or key, or the password is wrong</exception>
    public X509Certificate2 Load(CertificateOptions options, string? name = null)
    {
        Validate(options, name);
        if (options.File is not { } file || PasswordName(file, options) is not { } passwordName)
            return Open(options, []);

        var passwords = PasswordSource();
        if (!passwords.TryGetMaxDecryptedLength(passwordName, out var maxLength))
            throw MissingPassword(passwordName);

        var password = ArrayUtility.AllocatePinned<char>(maxLength);
        try
        {
            var length = passwords.Decrypt(passwordName, password.AsSpan());
            return Open(options, password.AsSpan(0, length));
        }
        finally
        {
            ArrayUtility.ZeroMemory(password.AsSpan());
        }
    }

    /// <summary>As <see cref="Load"/>, reading a file's password without blocking a thread.</summary>
    /// <param name="options">What to open</param>
    /// <param name="name">The options' name, for named options; it is only reported in a validation failure.</param>
    /// <param name="cancellationToken">Cancels reading the password</param>
    /// <exception cref="ArgumentNullException">options is null</exception>
    /// <exception cref="OptionsValidationException">The options aren't valid on this operating system</exception>
    /// <exception cref="InvalidOperationException">As for <see cref="Load"/></exception>
    /// <exception cref="KeyNotFoundException">The password source holds no secret by the name given</exception>
    /// <exception cref="CryptographicException">A file isn't a certificate or key, or the password is wrong</exception>
    public async Task<X509Certificate2> LoadAsync(CertificateOptions options, string? name = null, CancellationToken cancellationToken = default)
    {
        Validate(options, name);
        if (options.File is not { } file || PasswordName(file, options) is not { } passwordName)
            return Open(options, []);

        var passwords = PasswordSource();
        var maxLength = await passwords.GetMaxDecryptedLengthAsync(passwordName, cancellationToken).ConfigureAwait(false);
        if (maxLength == 0)
            throw MissingPassword(passwordName);

        // Pinned, so the awaits don't leave a copy anywhere the GC moved it from.
        var password = ArrayUtility.AllocatePinned<char>(maxLength);
        try
        {
            var length = await passwords.DecryptAsync(passwordName, password.AsMemory(), cancellationToken).ConfigureAwait(false);
            return Open(options, password.AsSpan(0, length));
        }
        finally
        {
            ArrayUtility.ZeroMemory(password.AsSpan());
        }
    }

    private void Validate(CertificateOptions options, string? name)
    {
        ArgumentNullException.ThrowIfNull(options);
        var result = _validator.Validate(name, options);
        if (result.Failed)
            throw new OptionsValidationException(name ?? Microsoft.Extensions.Options.Options.DefaultName, typeof(CertificateOptions), result.Failures);
    }

    // The secret a file's password is in; null when it has none to read. A PKCS#12 file needs its
    // password even for the certificate alone; a PEM certificate without its key needs none.
    private static string? PasswordName(CertificateFileOptions file, CertificateOptions options)
        => file.Format == CertificateFileFormat.Pkcs12 || options.RequirePrivateKey ? file.PasswordSecretName : null;

    private IProtectedReadOnlyCache PasswordSource()
        => _passwords ?? throw new InvalidOperationException(
            "The certificate's key file has a password, but the loader was given no password source to read it from.");

    private static KeyNotFoundException MissingPassword(string passwordName)
        => new($"The password source holds no secret named '{passwordName}'.");

    // Opens the one source options sets, which validation has made sure of, and checks the result.
    private X509Certificate2 Open(CertificateOptions options, ReadOnlySpan<char> password)
    {
        var certificate = options.Windows is { } windows ? FromStore(windows, options.RequirePrivateKey)
            : options.MacOS is { } macOS ? FromStore(macOS, options.RequirePrivateKey)
            : options.Linux is { } linux ? FromProvider(linux, options.RequirePrivateKey)
            : FromFile(options.File!, options.RequirePrivateKey, password);

        try
        {
            if (options.RequirePrivateKey && !certificate.HasPrivateKey)
                throw new InvalidOperationException($"The certificate '{certificate.Subject}' has no private key.");
            if (!IsValidNow(certificate))
                throw new InvalidOperationException(
                    $"The certificate '{certificate.Subject}' is valid from {certificate.NotBefore:u} to {certificate.NotAfter:u}, not now.");
            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    private X509Certificate2 FromStore(CertificateStoreOptions store, bool requirePrivateKey)
    {
        var subject = new X500DistinguishedName(store.Subject!).Name;
        using var found = new Disposing(_openStore(store.StoreName, store.StoreLocation));

        // Compared decoded, as each certificate states its subject, so how either side spells its
        // string types doesn't matter; ignoring case, as distinguished names compare.
        var named = found.Certificates.Where(c => string.Equals(c.SubjectName.Name, subject, StringComparison.OrdinalIgnoreCase)).ToList();
        var chosen = named.Where(c => IsValidNow(c) && (!requirePrivateKey || c.HasPrivateKey)).MaxBy(c => c.NotAfter);
        if (chosen is null)
        {
            throw new InvalidOperationException(named.Count == 0
                ? $"The {store.StoreLocation} {store.StoreName} store holds no certificate whose subject is '{store.Subject}'."
                : $"The {store.StoreLocation} {store.StoreName} store's {named.Count} certificate(s) whose subject is '{store.Subject}' are all "
                  + (requirePrivateKey ? "expired, not yet valid, or without a private key." : "expired or not yet valid."));
        }

        found.Keep(chosen);
        return chosen;
    }

    private X509Certificate2 FromFile(CertificateFileOptions file, bool requirePrivateKey, ReadOnlySpan<char> password)
    {
        if (file.Format == CertificateFileFormat.Pkcs12)
            return X509CertificateLoader.LoadPkcs12FromFile(file.Path!, password, KeyStorage);

        if (!requirePrivateKey)
            return X509CertificateLoader.LoadCertificateFromFile(file.Path!);

        var certificate = file.PasswordSecretName is null
            ? X509Certificate2.CreateFromPemFile(file.Path!, file.KeyPath)
            : X509Certificate2.CreateFromEncryptedPemFile(file.Path!, password, file.KeyPath);
        if (!_reimportPemKeys)
            return certificate;

        using (certificate)
            return Reimported(certificate);
    }

    // A PEM key is imported ephemeral, which SChannel can't present as a TLS server's key: moved into
    // a key like a PKCS#12 one's through an export, pinned and zeroed at once, and an import.
    private static X509Certificate2 Reimported(X509Certificate2 certificate)
    {
        var exported = certificate.Export(X509ContentType.Pkcs12);
        var pinned = ArrayUtility.AllocatePinned<byte>(exported.Length);
        try
        {
            exported.CopyTo(pinned, 0);
            ArrayUtility.ZeroMemory(exported);
            return X509CertificateLoader.LoadPkcs12(pinned, password: null, KeyStorage);
        }
        finally
        {
            ArrayUtility.ZeroMemory(pinned);
        }
    }

    private static X509Certificate2 FromProvider(LinuxOpenSslProviderOptions linux, bool requirePrivateKey)
    {
        var certificate = X509CertificateLoader.LoadCertificateFromFile(linux.CertificateFile!);
        if (!requirePrivateKey)
            return certificate;

        using (certificate)
            return WithProviderKey(certificate, linux.Provider, linux.KeyUri!);
    }

    // Linux only, which validation has checked: OpenSSL providers are how .NET reaches a key it
    // can't hold, and only Linux's .NET uses OpenSSL. Untestable off a Linux host with the provider,
    // as the README documents for the native bindings.
    [ExcludeFromCodeCoverage]
    private static X509Certificate2 WithProviderKey(X509Certificate2 certificate, string provider, string keyUri)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("An OpenSSL provider key can only be opened on Linux.");

        return OpenProviderKey(certificate, provider, keyUri);
    }

    [ExcludeFromCodeCoverage]
    [SupportedOSPlatform("linux")]
    private static X509Certificate2 OpenProviderKey(X509Certificate2 certificate, string provider, string keyUri)
    {
        // The certificate holds its own reference to the key, so these can be disposed.
        using var key = SafeEvpPKeyHandle.OpenKeyFromProvider(provider, keyUri);
        switch (certificate.GetKeyAlgorithm())
        {
            case RsaAlgorithm:
                using (var rsa = new RSAOpenSsl(key))
                    return certificate.CopyWithPrivateKey(rsa);
            case EcAlgorithm:
                using (var ecdsa = new ECDsaOpenSsl(key))
                    return certificate.CopyWithPrivateKey(ecdsa);
            case var algorithm:
                throw new CryptographicException($"The certificate's key algorithm ({algorithm}) isn't RSA or ECDSA.");
        }
    }

    private bool IsValidNow(X509Certificate2 certificate)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        return certificate.NotBefore.ToUniversalTime() <= now && now <= certificate.NotAfter.ToUniversalTime();
    }

    // The store's certificates, read-only. A store that doesn't exist reads as empty.
    [ExcludeFromCodeCoverage(Justification = "The operating system's own store; the tests read their own collections instead.")]
    private static X509Certificate2Collection ReadStore(StoreName name, StoreLocation location)
    {
        using var store = new X509Store(name, location);
        try
        {
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        }
        catch (CryptographicException)
        {
            return [];
        }

        return store.Certificates;
    }

    // Disposes every certificate a store read gave, but the one kept.
    private sealed class Disposing(X509Certificate2Collection certificates) : IDisposable
    {
        private X509Certificate2? _kept;

        public X509Certificate2Collection Certificates { get; } = certificates;

        public void Keep(X509Certificate2 certificate) => _kept = certificate;

        public void Dispose()
        {
            foreach (var certificate in Certificates)
            {
                if (!ReferenceEquals(certificate, _kept))
                    certificate.Dispose();
            }
        }
    }
}
