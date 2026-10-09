using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Loads the Windows native KMS library from its one installed location and nowhere else. This
/// library receives every plaintext DEK on unwrap and chooses every "random" DEK on
/// generate-and-wrap, so loading an impostor would hand over every key. The default P/Invoke
/// probe would search the application directory and then PATH; this loader replaces that with
/// four checks, all of which must pass before the file is mapped:
/// <list type="number">
/// <item>The file exists at <c>%ProgramFiles%\HkdfGuard\v1\HkdfGuardV1.dll</c>. The Program Files
/// location comes from the Windows known-folder registry setting, which only an administrator can
/// change, not from the <c>ProgramFiles</c> environment variable.</item>
/// <item>No component of that path, from the file up to (not including) the drive root, is a
/// reparse point - a symlink or junction could redirect a trusted-looking path somewhere
/// writable.</item>
/// <item>Every one of those components is owned by, and writable only by, SYSTEM, Administrators,
/// or TrustedInstaller - so nobody without administrative rights could have replaced the file,
/// renamed a parent folder, or rewritten an ACL to allow either.</item>
/// <item>The file carries a valid Authenticode signature chaining to a trusted root, issued to
/// <see cref="ExpectedPublisher"/>.</item>
/// </list>
/// The library's own dependencies are then resolved from System32 only. Any failed check throws;
/// there is deliberately no fallback to the default search and no override of the path.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsNativeLibraryLoader
{
    internal const string FileName = "HkdfGuardV1.dll";

    /// <summary>
    /// The Authenticode signer subject the library must carry. The signing certificate is
    /// short-lived and reissued frequently, so a thumbprint can't be pinned; the subject is
    /// identity-verified by the issuing CA, and the chain itself must be trusted.
    /// </summary>
    internal const string ExpectedPublisher = "CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US";

    // NT SERVICE\TrustedInstaller has no WellKnownSidType; this is its fixed service SID.
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    private static readonly SecurityIdentifier[] TrustedPrincipals =
    [
        new(WellKnownSidType.LocalSystemSid, null),
        new(WellKnownSidType.BuiltinAdministratorsSid, null),
        TrustedInstaller,
    ];

    // Any right that lets a principal change what this path loads: write or append data,
    // delete or rename (Delete on the item, DeleteSubdirectoriesAndFiles on its parent), write
    // extended attributes, or take over the ACL. Generic bits are listed too, since an ACE can
    // carry them unmapped.
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    private const FileSystemRights WriteRights = FileSystemRights.WriteData
                                                 | FileSystemRights.AppendData
                                                 | FileSystemRights.WriteExtendedAttributes
                                                 | FileSystemRights.DeleteSubdirectoriesAndFiles
                                                 | FileSystemRights.Delete
                                                 | FileSystemRights.ChangePermissions
                                                 | FileSystemRights.TakeOwnership;

    private static readonly Lock Gate = new();
    private static IntPtr _handle;

    /// <summary>The single location the library is loaded from.</summary>
    internal static string InstalledPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolderOption.DoNotVerify),
        "HkdfGuard", "v1", FileName);

    /// <summary>
    /// Verifies and loads the installed library, once per process; later calls return the same
    /// handle. A failure isn't cached, so a fixed installation is picked up on the next call.
    /// </summary>
    /// <exception cref="DllNotFoundException">The library isn't installed at <see cref="InstalledPath"/>.</exception>
    /// <exception cref="SecurityException">The installed file or its location failed verification.</exception>
    public static IntPtr Load()
    {
        lock (Gate)
        {
            if (_handle == IntPtr.Zero)
                _handle = Load(InstalledPath, ExpectedPublisher);
            return _handle;
        }
    }

    internal static IntPtr Load(string path, string expectedPublisher)
    {
        if (!File.Exists(path))
            throw new DllNotFoundException(
                $"The HkdfGuard native KMS library is not installed at '{path}'. Install it there; it is never loaded from anywhere else.");

        VerifyLocation(path);
        VerifySignature(path, expectedPublisher);

        // Absolute path, so no probing for the library itself; its own imports (kernel32,
        // advapi32, ncrypt) come from System32 only, never the application directory or PATH.
        return NativeLibrary.Load(path, typeof(WindowsNativeLibraryLoader).Assembly, DllImportSearchPath.System32);
    }

    /// <summary>
    /// Checks the file and each parent folder below the drive root: not a reparse point, and
    /// owned and writable only by trusted principals.
    /// </summary>
    /// <exception cref="SecurityException">A path component failed a check.</exception>
    internal static void VerifyLocation(string path)
    {
        FileSystemInfo? item = new FileInfo(Path.GetFullPath(path));
        while (item is not null)
        {
            var parent = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent;
            if (parent is null)
                break; // the drive root itself: renaming beneath it needs rights on the child, checked below

            VerifyNotReparsePoint(item);
            var security = item is FileInfo f
                ? (FileSystemSecurity)f.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : ((DirectoryInfo)item).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            VerifyTrustedOnly(security, item.FullName);

            item = parent;
        }
    }

    internal static void VerifyNotReparsePoint(FileSystemInfo item)
    {
        if (item.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new SecurityException(
                $"'{item.FullName}' is a symbolic link or junction; the HkdfGuard native library is only loaded through a real path.");
    }

    /// <summary>
    /// Requires a trusted owner and no Allow entry granting any write right to anyone else.
    /// Inherit-only entries don't apply to this item, and Deny entries can only remove access, so
    /// both are ignored.
    /// </summary>
    /// <exception cref="SecurityException">The owner is untrusted, or an untrusted principal can write.</exception>
    internal static void VerifyTrustedOnly(FileSystemSecurity security, string displayPath)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !IsTrusted(owner))
            throw new SecurityException(
                $"'{displayPath}' is owned by {Describe(owner)}; the HkdfGuard native library is only loaded from a location owned by SYSTEM, Administrators, or TrustedInstaller.");

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly))
                continue;

            var rights = (int)rule.FileSystemRights;
            var grantsWrite = (rights & ((int)WriteRights | GenericAll | GenericWrite)) != 0;
            if (grantsWrite && !IsTrusted((SecurityIdentifier)rule.IdentityReference))
                throw new SecurityException(
                    $"'{displayPath}' grants {rule.FileSystemRights} to {Describe(rule.IdentityReference)}; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.");
        }
    }

    /// <summary>
    /// Requires a valid Authenticode signature that chains to a trusted root, issued to
    /// <paramref name="expectedPublisher"/>.
    /// </summary>
    /// <exception cref="SecurityException">The signature is missing, invalid, untrusted, or from another publisher.</exception>
    internal static void VerifySignature(string path, string expectedPublisher)
    {
        var status = WinTrust.VerifyEmbeddedSignature(path);
        if (status != 0)
            throw new SecurityException(
                $"'{path}' does not carry a valid, trusted Authenticode signature (WinVerifyTrust status 0x{status:X8}).");

        // A file WinVerifyTrust just accepted always has a readable signer; were that ever not so,
        // this throws and the load still fails closed.
#pragma warning disable SYSLIB0057 // The only API that reads an Authenticode signer; the signature itself was verified above.
        using var signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        var subject = signer.Subject;

        if (!string.Equals(subject, expectedPublisher, StringComparison.Ordinal))
            throw new SecurityException(
                $"'{path}' is signed by '{subject}', not the expected HkdfGuard publisher '{expectedPublisher}'.");
    }

    private static bool IsTrusted(SecurityIdentifier sid) => Array.IndexOf(TrustedPrincipals, sid) >= 0;

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
