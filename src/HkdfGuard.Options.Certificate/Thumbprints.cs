using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HkdfGuard.Options.Certificate;

/// <summary>
/// The thumbprint rule <see cref="CertificateOptions.Thumbprint"/> follows: a certificate's SHA-1
/// (40 hex digits) or SHA-256 (64 hex digits) hash, written however an administrator copied it.
/// </summary>
internal static class Thumbprints
{
    /// <summary>
    /// The thumbprint as upper-case hex alone, with spaces, colons, hyphens and the invisible
    /// direction marks Windows' certificate dialog copies along removed; null if what's left isn't
    /// 40 or 64 hex digits, or if <paramref name="thumbprint"/> is null.
    /// </summary>
    public static string? Normalize(string? thumbprint)
    {
        if (thumbprint is null)
            return null;

        Span<char> hex = stackalloc char[thumbprint.Length];
        var length = 0;
        foreach (var c in thumbprint)
        {
            if (c is ' ' or '\t' or ':' or '-' or '‎' or '‏' or '﻿')
                continue;
            if (!char.IsAsciiHexDigit(c))
                return null;
            hex[length++] = char.ToUpperInvariant(c);
        }

        return length is 40 or 64 ? new string(hex[..length]) : null;
    }

    /// <summary>Whether certificate's hash - SHA-1 or SHA-256, by the normalized thumbprint's length - is it.</summary>
    public static bool Matches(X509Certificate2 certificate, string normalized)
    {
        var actual = normalized.Length == 40
            ? certificate.Thumbprint
            : certificate.GetCertHashString(HashAlgorithmName.SHA256);
        return string.Equals(actual, normalized, StringComparison.OrdinalIgnoreCase);
    }
}
