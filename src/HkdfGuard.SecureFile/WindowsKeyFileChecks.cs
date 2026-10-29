using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HkdfGuard.SecureFile;

/// <summary>
/// Decides whether a file on Windows - a key file, or any file TrustedFile reads - can be trusted,
/// by the native library's (hkdfguard_open_file's) rules:
/// <list type="bullet">
/// <item>The path names a file on a local fixed drive. UNC paths, device paths (\\?\, \\.\) and
/// network drives are refused before anything is opened, so no server named in a path is ever
/// contacted.</item>
/// <item>The opened file's final path - with every symbolic link, junction, mount point and
/// substituted drive resolved - is the path that was asked for, once Path.GetFullPath has
/// expanded any 8.3 short name (it expands each one that exists on disk; a path still spelled
/// with a short name doesn't match the final path and is refused). So nothing on the path
/// redirects it, and the folders checked are the ones the file is in.</item>
/// <item>The file, and every folder above it, is owned by a trusted principal, and grants no one
/// else any right to write, append, delete, rename, change its permissions or take ownership.
/// For a folder that also covers creating files and folders in it. The drive root is held only to
/// what could rename or delete what's beneath it, since a default C:\ lets Authenticated Users
/// create folders.</item>
/// </list>
/// Trusted principals are SYSTEM, Administrators, TrustedInstaller and
/// <see cref="KeyFileTrust.WindowsPrincipals"/>.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsKeyFileChecks
{
    // NT SERVICE\TrustedInstaller has no WellKnownSidType; this is its fixed service SID.
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    private static readonly SecurityIdentifier[] AlwaysTrusted =
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        TrustedInstaller,
    ];

    // Groups every account, or every signed-in one, is in: trusting one trusts everybody.
    private static readonly SecurityIdentifier[] NeverTrusted =
    [
        new(WellKnownSidType.WorldSid, null),
        new(WellKnownSidType.AuthenticatedUserSid, null),
        new(WellKnownSidType.BuiltinUsersSid, null),
        new(WellKnownSidType.InteractiveSid, null),
        new(WellKnownSidType.AnonymousSid, null),
    ];

    // Any right that lets a principal change what this path reads: write or append data (on a
    // folder, create files or folders), delete or rename (Delete on the item,
    // DeleteSubdirectoriesAndFiles on its parent), write extended attributes, or take over the
    // ACL. Generic bits are listed too, since an ACE can carry them unmapped.
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    private const FileSystemRights WriteRights = FileSystemRights.WriteData
                                                 | FileSystemRights.AppendData
                                                 | FileSystemRights.WriteExtendedAttributes
                                                 | FileSystemRights.DeleteSubdirectoriesAndFiles
                                                 | FileSystemRights.Delete
                                                 | FileSystemRights.ChangePermissions
                                                 | FileSystemRights.TakeOwnership;

    internal const int GuardedRights = (int)WriteRights | GenericAll | GenericWrite;

    // On the drive root, only what lets a principal rename or delete an entry directly beneath it.
    internal const int GuardedRootRights = (int)(FileSystemRights.DeleteSubdirectoriesAndFiles
                                                 | FileSystemRights.ChangePermissions
                                                 | FileSystemRights.TakeOwnership)
                                           | GenericAll;

    /// <summary>The principals <paramref name="trust"/> trusts, the always-trusted ones included.</summary>
    /// <exception cref="ArgumentException">A listed SID isn't valid, or is one that every account is in.</exception>
    internal static SecurityIdentifier[] TrustedPrincipals(KeyFileTrust trust)
    {
        var trusted = new List<SecurityIdentifier>(AlwaysTrusted);
        foreach (var value in trust.WindowsPrincipals)
        {
            SecurityIdentifier sid;
            try
            {
                sid = new SecurityIdentifier(value);
            }
            catch (ArgumentException e)
            {
                throw new ArgumentException($"KeyFileTrust.WindowsPrincipals holds '{value}', which is not a security identifier (S-1-...).", e);
            }

            if (Array.IndexOf(NeverTrusted, sid) >= 0)
                throw new ArgumentException(
                    $"KeyFileTrust.WindowsPrincipals holds {Describe(sid)}, which every account (or every signed-in one) is in; trusting it would trust anyone to replace a trusted file.");
            trusted.Add(sid);
        }

        return [.. trusted];
    }

    /// <summary>
    /// Refuses a path that isn't on a local fixed drive, before anything is opened.
    /// </summary>
    /// <param name="fullPath">The absolute path (Path.GetFullPath).</param>
    /// <param name="driveType">The type of the drive the path's root names.</param>
    /// <exception cref="UnauthorizedAccessException">It isn't.</exception>
    internal static void VerifyPathForm(string fullPath, DriveType driveType)
    {
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal) || fullPath.StartsWith("//", StringComparison.Ordinal))
            throw Untrusted(fullPath, "it is a UNC or device path; trusted files are only read from a local drive");

        if (driveType != DriveType.Fixed)
            throw Untrusted(fullPath, $"it is on a {driveType} drive; trusted files are only read from a local fixed drive");
    }

    /// <summary>
    /// Requires the opened file's final path to be the one that was asked for.
    /// </summary>
    /// <param name="fullPath">The absolute path that was opened.</param>
    /// <param name="finalPath">GetFinalPathNameByHandle's answer for the opened handle (\\?\C:\...).</param>
    /// <exception cref="UnauthorizedAccessException">They differ.</exception>
    internal static void VerifyFinalPath(string fullPath, string finalPath)
    {
        const string LocalPrefix = @"\\?\";
        var opened = finalPath.StartsWith(LocalPrefix, StringComparison.Ordinal) && !finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)
            ? finalPath[LocalPrefix.Length..]
            : null;

        if (opened is null || !string.Equals(opened, fullPath, StringComparison.OrdinalIgnoreCase))
            throw Untrusted(fullPath,
                $"it opens '{finalPath}' - its path runs through a symbolic link, junction, mount point or substituted drive. Configure it as the full, real path");
    }

    /// <summary>Refuses a folder that is a symbolic link, junction or other reparse point.</summary>
    internal static void VerifyNotReparsePoint(FileAttributes attributes, string fullPath, string folder)
    {
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
            throw Untrusted(fullPath, $"'{folder}' is a symbolic link, junction or other reparse point");
    }

    /// <summary>
    /// Requires a trusted owner, and no Allow entry granting any of
    /// <paramref name="guardedRights"/> (<see cref="GuardedRights"/> for the file and folders,
    /// <see cref="GuardedRootRights"/> for the drive root) to anyone else. Inherit-only entries
    /// don't apply to the item itself, and Deny entries can only remove access, so both are ignored.
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">The owner is untrusted, or an untrusted principal holds a guarded right.</exception>
    internal static void VerifyTrustedOnly(FileSystemSecurity security, string fullPath, string item, int guardedRights, SecurityIdentifier[] trusted)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || Array.IndexOf(trusted, owner) < 0)
            throw Untrusted(fullPath, $"'{item}' is owned by {Describe(owner)}, not SYSTEM, Administrators, TrustedInstaller or a trusted deployer");

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                continue;

            if (((int)rule.FileSystemRights & guardedRights) != 0 && Array.IndexOf(trusted, (SecurityIdentifier)rule.IdentityReference) < 0)
                throw Untrusted(fullPath, $"'{item}' grants {rule.FileSystemRights} to {Describe(rule.IdentityReference)}");
        }
    }

    private static UnauthorizedAccessException Untrusted(string path, string why)
        => new($"'{path}' is not trusted: {why}. Keep it in a folder of its own that only administrators (or a trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.");

    private static string Describe(IdentityReference? identity)
    {
        if (identity is null)
            return "an unknown principal";

        try
        {
            return $"{identity.Translate(typeof(NTAccount))} ({identity})";
        }
        catch (IdentityNotMappedException)
        {
            return identity.ToString();
        }
    }
}
