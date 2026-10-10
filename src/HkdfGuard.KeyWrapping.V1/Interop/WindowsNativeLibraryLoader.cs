using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Loads the Windows native KMS library from its one installed location and nowhere else. This
/// library receives every plaintext DEK on unwrap and chooses every "random" DEK on
/// generate-and-wrap, so loading an impostor would hand over every key. The default P/Invoke
/// probe would search the application directory and then PATH; this loader replaces that with
/// five checks, all of which must pass before the file is mapped:
/// <list type="number">
/// <item>The file exists at <c>%ProgramFiles%\HkdfGuard\v1\HkdfGuardV1.dll</c>. The Program Files
/// location comes from the Windows known-folder registry setting, which only an administrator can
/// change, not from the <c>ProgramFiles</c> environment variable.</item>
/// <item>No component of that path, from the file up to (not including) the drive root, is a
/// reparse point - a symlink or junction could redirect a trusted-looking path somewhere
/// writable.</item>
/// <item>Every one of those components is owned by, and writable only by, SYSTEM, Administrators,
/// or TrustedInstaller - so nobody without administrative rights could have replaced the file,
/// renamed a parent folder, or rewritten an ACL to allow either. The drive root is held only to
/// what could rename the folder beneath it: a trusted owner, and delete-child or ACL rights for
/// trusted principals alone.</item>
/// <item>The file carries a valid Authenticode signature issued to <see cref="ExpectedPublisher"/>
/// for code signing under HkdfGuard's Artifact Signing profile (<see cref="ExpectedProfileEku"/>),
/// whose chain - as WinVerifyTrust validated it - ends at the pinned root
/// <see cref="ExpectedRootSha256"/>.</item>
/// <item>Its PE header - covered by that signature - marks it a DLL for this process's
/// architecture. Everything the HkdfGuard profile signs passes the signer checks, so this refuses
/// its other binaries, such as hkdfguard-v1-initialize.exe renamed into place.</item>
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
    /// identity-verified by the issuing CA. A subject alone proves nothing, though - any root the
    /// machine trusts could issue a certificate with it - so the root and profile are pinned too.
    /// </summary>
    internal const string ExpectedPublisher = "CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US";

    /// <summary>
    /// SHA-256 of the root the signer's chain must end at: Microsoft Identity Verification Root
    /// Certificate Authority 2020, the root of Azure Artifact Signing. Without it, any root trusted
    /// on the machine - including one a non-administrator added to their own CurrentUser\Root
    /// store - could vouch for <see cref="ExpectedPublisher"/>. Compared by hash, never by name.
    /// </summary>
    /// <remarks>
    /// Only the root is pinned. Artifact Signing reissues the leaf every few days and rotates its
    /// intermediate CAs ("Microsoft ID Verified CS EOC CA 0x"), so pinning either would break
    /// every future release; <see cref="ExpectedProfileEku"/> identifies the leaf instead.
    /// </remarks>
    internal const string ExpectedRootSha256 = "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270";

    /// <summary>
    /// The EKU identifying HkdfGuard's Artifact Signing certificate profile. Every leaf reissued
    /// under the profile carries it; other Artifact Signing customers' leaves carry their own. Not
    /// to be confused with 1.3.6.1.4.1.311.97.1.0, which every Artifact Signing leaf carries.
    /// </summary>
    internal const string ExpectedProfileEku = "1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563";

    /// <summary>The Code Signing EKU (id-kp-codeSigning), required of the leaf.</summary>
    internal const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";

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

    private const int GuardedRights = (int)WriteRights | GenericAll | GenericWrite;

    // On the drive root, only what lets a principal rename or delete an entry directly beneath it -
    // delete-child, or taking over the ACL to grant it. Creating new entries there (Authenticated
    // Users may, on a default C:\) can't affect this path, and GENERIC_WRITE doesn't include any of these.
    private const int GuardedRootRights = (int)(FileSystemRights.DeleteSubdirectoriesAndFiles
                                                | FileSystemRights.ChangePermissions
                                                | FileSystemRights.TakeOwnership)
                                          | GenericAll;

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
        VerifyImageKind(path);

        // Absolute path, so no probing for the library itself; its own imports (kernel32,
        // advapi32, ncrypt) come from System32 only, never the application directory or PATH.
        return NativeLibrary.Load(path, typeof(WindowsNativeLibraryLoader).Assembly, DllImportSearchPath.System32);
    }

    /// <summary>
    /// Checks the file and each parent folder below the drive root: not a reparse point, and
    /// owned and writable only by trusted principals. The drive root itself must be owned by a
    /// trusted principal and let no one else rename or delete what's directly beneath it - delete-
    /// child on a folder renames any child, whatever the child's own ACL says.
    /// </summary>
    /// <exception cref="SecurityException">A path component failed a check.</exception>
    internal static void VerifyLocation(string path)
    {
        FileSystemInfo? item = new FileInfo(Path.GetFullPath(path));
        while (item is not null)
        {
            var parent = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent;
            if (parent is null)
            {
                var rootSecurity = ((DirectoryInfo)item).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                VerifyDriveRoot(rootSecurity, item.FullName);
                break;
            }

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
        => VerifyTrustedOnly(security, displayPath, GuardedRights);

    /// <summary>
    /// The drive root's form of <see cref="VerifyTrustedOnly(FileSystemSecurity, string)"/>: only
    /// the rights that could rename or delete an entry beneath it are refused.
    /// </summary>
    internal static void VerifyDriveRoot(FileSystemSecurity security, string displayPath)
        => VerifyTrustedOnly(security, displayPath, GuardedRootRights);

    private static void VerifyTrustedOnly(FileSystemSecurity security, string displayPath, int guardedRights)
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
            var grantsWrite = (rights & guardedRights) != 0;
            if (grantsWrite && !IsTrusted((SecurityIdentifier)rule.IdentityReference))
                throw new SecurityException(
                    $"'{displayPath}' grants {rule.FileSystemRights} to {Describe(rule.IdentityReference)}; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.");
        }
    }

    /// <summary>
    /// What <see cref="VerifySignature(string, string, Func{string, VerifiedSigner})"/> checks,
    /// read from a signature WinVerifyTrust has already accepted.
    /// </summary>
    /// <param name="LeafSubject">The signing certificate's subject.</param>
    /// <param name="LeafEkuOids">The signing certificate's EKU OIDs; empty if it has no EKU extension.</param>
    /// <param name="RootSha256">The SHA-256 of the root certificate the chain ends at, as hex.</param>
    internal readonly record struct VerifiedSigner(string LeafSubject, IReadOnlyCollection<string> LeafEkuOids, string RootSha256);

    /// <summary>
    /// Requires a valid, trusted Authenticode signature whose signer passes
    /// <see cref="VerifySignerIdentity"/> for <paramref name="expectedPublisher"/>.
    /// </summary>
    /// <exception cref="SecurityException">The signature is missing, invalid, untrusted, or from another signer.</exception>
    internal static void VerifySignature(string path, string expectedPublisher)
        => VerifySignature(path, expectedPublisher, ReadVerifiedSigner);

    /// <param name="path">The library.</param>
    /// <param name="expectedPublisher">The leaf subject required.</param>
    /// <param name="readSigner">Verifies the signature and reads its signer; throws <see cref="SecurityException"/> if the signature isn't valid and trusted.</param>
    /// <exception cref="SecurityException">The signer couldn't be read, or failed a check. Any other failure is reported as this too.</exception>
    internal static void VerifySignature(string path, string expectedPublisher, Func<string, VerifiedSigner> readSigner)
    {
        VerifiedSigner signer;
        try
        {
            signer = readSigner(path);
        }
        catch (Exception e) when (e is not SecurityException)
        {
            throw new SecurityException($"Could not read the Authenticode signer of '{path}'; refusing to load it.", e);
        }

        VerifySignerIdentity(path, signer.LeafSubject, signer.LeafEkuOids, signer.RootSha256, expectedPublisher);
    }

    /// <summary>
    /// The signer policy: the leaf is issued to <paramref name="expectedPublisher"/>, carries the
    /// Code Signing EKU and <see cref="ExpectedProfileEku"/>, and its chain ends at
    /// <see cref="ExpectedRootSha256"/>. The chain's trust is WinVerifyTrust's to decide, not this.
    /// </summary>
    /// <exception cref="SecurityException">Any requirement isn't met.</exception>
    internal static void VerifySignerIdentity(string path, string leafSubject, IReadOnlyCollection<string> leafEkuOids, string rootSha256, string expectedPublisher)
    {
        if (!string.Equals(leafSubject, expectedPublisher, StringComparison.Ordinal))
            throw new SecurityException(
                $"'{path}' is signed by '{leafSubject}', not the expected HkdfGuard publisher '{expectedPublisher}'.");

        if (!string.Equals(rootSha256, ExpectedRootSha256, StringComparison.OrdinalIgnoreCase))
            throw new SecurityException(
                $"'{path}' is signed under a root with SHA-256 {rootSha256}, not Microsoft Identity Verification Root Certificate Authority 2020 ({ExpectedRootSha256}), which HkdfGuard is signed under.");

        if (!leafEkuOids.Contains(CodeSigningEku, StringComparer.Ordinal))
            throw new SecurityException(
                $"'{path}' is signed with a certificate not issued for code signing (no EKU {CodeSigningEku}).");

        if (!leafEkuOids.Contains(ExpectedProfileEku, StringComparer.Ordinal))
            throw new SecurityException(
                $"'{path}' is signed with a certificate not issued under HkdfGuard's Artifact Signing profile (no EKU {ExpectedProfileEku}).");
    }

    /// <summary>
    /// Verifies the signature with WinVerifyTrust and reads the signer from the chain it validated,
    /// rather than building a second chain that might differ from it.
    /// </summary>
    /// <exception cref="SecurityException">The signature is missing, invalid, or untrusted.</exception>
    internal static VerifiedSigner ReadVerifiedSigner(string path)
    {
        var status = WinTrust.VerifyEmbeddedSignature(path, out var chain);
        if (status != 0)
            throw new SecurityException(
                $"'{path}' does not carry a valid, trusted Authenticode signature (WinVerifyTrust status 0x{status:X8}).");

        // A zero status always comes with a chain, leaf first; were that ever not so, this throws
        // and VerifySignature still fails closed.
        using (chain)
        {
            var elements = chain!.ChainElements;
            try
            {
                var leaf = elements[0].Certificate;
                var ekuOids = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                    .SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>())
                    .Select(oid => oid.Value ?? "")
                    .ToArray();
                var rootSha256 = elements[^1].Certificate.GetCertHashString(HashAlgorithmName.SHA256);
                return new VerifiedSigner(leaf.Subject, ekuOids, rootSha256);
            }
            finally
            {
                foreach (var element in elements)
                    element.Certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// Requires the file's PE header to mark it a DLL built for this process's architecture. Run
    /// after <see cref="VerifySignature(string, string)"/>, whose hash covers the header.
    /// </summary>
    /// <exception cref="SecurityException">It isn't, or the header can't be read.</exception>
    internal static void VerifyImageKind(string path)
    {
        Characteristics characteristics;
        Machine machine;
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new PEReader(stream);
            var header = reader.PEHeaders.CoffHeader;
            (characteristics, machine) = (header.Characteristics, header.Machine);
        }
        catch (Exception e) when (e is not SecurityException)
        {
            throw new SecurityException($"Could not read the PE header of '{path}'; refusing to load it.", e);
        }

        VerifyImageKind(path, characteristics, machine, RuntimeInformation.ProcessArchitecture);
    }

    /// <summary>The policy half of <see cref="VerifyImageKind(string)"/>.</summary>
    /// <exception cref="SecurityException">Not a DLL, or not for <paramref name="processArchitecture"/>.</exception>
    internal static void VerifyImageKind(string path, Characteristics characteristics, Machine machine, Architecture processArchitecture)
    {
        if (!characteristics.HasFlag(Characteristics.Dll))
            throw new SecurityException(
                $"'{path}' is signed by the HkdfGuard publisher but is not a DLL (an executable renamed into place?); refusing to load it.");

        Machine? expected = processArchitecture switch
        {
            Architecture.X64 => Machine.Amd64,
            Architecture.Arm64 => Machine.Arm64,
            Architecture.X86 => Machine.I386,
            _ => null,
        };
        if (machine != expected)
            throw new SecurityException(
                $"'{path}' is built for {machine}, but this is a {processArchitecture} process; refusing to load it.");
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
