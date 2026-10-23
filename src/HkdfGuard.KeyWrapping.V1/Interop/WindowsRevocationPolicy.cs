using System.Security;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// What the Windows loader's revocation pass (<c>WinTrust.CheckRevocation</c>) decides: the load is
/// refused only when Windows definitively reports a certificate in the signer's chain revoked. Any
/// other result - success, revocation servers unreachable, no revocation information, or any other
/// failure - lets the load continue, so a host with no network still starts. The signature and the
/// pinned signer were already validated by the first pass; this pass only adds revocation.
/// No Windows calls, so it is tested on every platform.
/// </summary>
internal static class WindowsRevocationPolicy
{
    /// <summary>CERT_E_REVOKED: a certificate was explicitly revoked by its issuer.</summary>
    internal const int CertificateRevoked = unchecked((int)0x800B010C);

    /// <summary>Whether a revocation pass that returned <paramref name="status"/> refuses the load.</summary>
    internal static bool Refuses(int status) => status == CertificateRevoked;

    /// <summary>Throws if <paramref name="status"/> refuses loading <paramref name="path"/>.</summary>
    /// <exception cref="SecurityException">A certificate in the signer's chain has been revoked.</exception>
    internal static void Verify(string path, int status)
    {
        if (Refuses(status))
            throw new SecurityException(
                $"'{path}' is signed with a certificate that has been revoked; refusing to load it. Install a current release.");
    }
}
