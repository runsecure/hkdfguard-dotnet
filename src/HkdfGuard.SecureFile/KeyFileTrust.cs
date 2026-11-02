namespace HkdfGuard.SecureFile;

/// <summary>
/// Who, besides the operating system's administrators, <see cref="TrustedKeyFile"/> trusts to have
/// written a key file it reads. A key file and every folder above it must be owned by a trusted
/// principal, and no one else may write, replace, rename or re-permission any of them: whoever can
/// replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt with a
/// network KMS key can - chooses the DEK new data is encrypted under.
/// <para>
/// Always trusted: SYSTEM, Administrators and TrustedInstaller on Windows; root on Linux and
/// macOS. <see cref="AdministratorsOnly"/> trusts no one else, which is the default. Add the
/// account or group your deployment writes key files as - never the account the application runs
/// as, unless it is a developer machine: an application that can rewrite its own key files can be
/// made to roll back to an older one.
/// </para>
/// <para>
/// <see cref="TrustedFile"/> holds secret files, certificates and any other file it reads to the
/// same rules, with the same trust.
/// </para>
/// </summary>
public sealed class KeyFileTrust
{
    /// <summary>Trusts only the operating system's administrators. The default.</summary>
    public static KeyFileTrust AdministratorsOnly { get; } = new();

    /// <summary>
    /// Windows security identifiers (SIDs, such as a deployers group's "S-1-5-21-...-1005") that
    /// may also own, and hold write rights on, a key file and the folders above it. Everyone,
    /// Authenticated Users, Users, Interactive and Anonymous are refused when a key file is read.
    /// </summary>
    public IReadOnlyList<string> WindowsPrincipals { get; init; } = [];

    /// <summary>Linux and macOS user ids that may also own a key file, the directories above it, and the symbolic links on its path.</summary>
    public IReadOnlyList<uint> UnixUserIds { get; init; } = [];

    /// <summary>
    /// Linux and macOS group ids whose members may write a key file or a directory above it: a
    /// group-writable file or directory is refused unless its group is listed. Writable by others
    /// is refused whatever is listed.
    /// </summary>
    public IReadOnlyList<uint> UnixGroupIds { get; init; } = [];
}
