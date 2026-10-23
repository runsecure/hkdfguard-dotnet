using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using HkdfGuard.SecureFile;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.SecureFile.Test;

/// <summary>
/// The Windows key-file location rules, checked against in-memory security descriptors and paths.
/// TrustedKeyFileTests runs them against real files.
/// </summary>
[SupportedOSPlatform("windows")]
public class WindowsKeyFileChecksTests
{
    private const string KeyFile = @"C:\HkdfGuardKeys\myapp\v1.key";

    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier AuthenticatedUsers = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier Deployers = new("S-1-5-21-1111111111-2222222222-3333333333-1005");

    private static SecurityIdentifier[] Trusted(params string[] extra)
        => WindowsKeyFileChecks.TrustedPrincipals(new KeyFileTrust { WindowsPrincipals = extra });

    private static FileSecurity Security(SecurityIdentifier owner, params (SecurityIdentifier Who, FileSystemRights Rights)[] allows)
    {
        var security = new FileSecurity();
        security.SetOwner(owner);
        foreach (var (who, rights) in allows)
            security.AddAccessRule(new FileSystemAccessRule(who, rights, AccessControlType.Allow));
        return security;
    }

    private static FileSecurity Locked(SecurityIdentifier owner) => Security(owner,
        (System, FileSystemRights.FullControl),
        (Administrators, FileSystemRights.FullControl),
        (TrustedInstaller, FileSystemRights.FullControl),
        (Users, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize));

    [WindowsFact]
    public void TrustedPrincipals_AlwaysIncludeSystemAdministratorsAndTrustedInstaller()
    {
        Assert.Equal([System, Administrators, TrustedInstaller], Trusted());
    }

    [WindowsFact]
    public void TrustedPrincipals_AddTheListedDeployers()
    {
        Assert.Contains(Deployers, Trusted(Deployers.Value));
    }

    [WindowsTheory]
    [InlineData("S-1-1-0")]      // Everyone
    [InlineData("S-1-5-11")]     // Authenticated Users
    [InlineData("S-1-5-32-545")] // Users
    [InlineData("S-1-5-4")]      // Interactive
    [InlineData("S-1-5-7")]      // Anonymous
    public void TrustedPrincipals_RefuseGroupsEveryoneIsIn(string sid)
    {
        var ex = Assert.Throws<ArgumentException>(() => Trusted(sid));
        Assert.Contains("every account", ex.Message);
    }

    [WindowsFact]
    public void TrustedPrincipals_RefuseSomethingThatIsNotASid()
    {
        var ex = Assert.Throws<ArgumentException>(() => Trusted("HkdfGuardDeployers"));
        Assert.Contains("not a security identifier", ex.Message);
    }

    [WindowsFact]
    public void VerifyPathForm_LocalFixedDrive_Passes()
        => WindowsKeyFileChecks.VerifyPathForm(KeyFile, DriveType.Fixed);

    [WindowsTheory]
    [InlineData(@"\\server\share\v1.key")]
    [InlineData(@"\\?\C:\HkdfGuardKeys\v1.key")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData("//server/share/v1.key")]
    public void VerifyPathForm_UncAndDevicePaths_AreRefused(string path)
    {
        var ex = Assert.Throws<UnauthorizedAccessException>(() => WindowsKeyFileChecks.VerifyPathForm(path, DriveType.Fixed));
        Assert.Contains("UNC or device path", ex.Message);
    }

    [WindowsTheory]
    [InlineData(DriveType.Network)]
    [InlineData(DriveType.Removable)]
    [InlineData(DriveType.CDRom)]
    [InlineData(DriveType.Ram)]
    [InlineData(DriveType.NoRootDirectory)]
    [InlineData(DriveType.Unknown)]
    public void VerifyPathForm_OtherDrives_AreRefused(DriveType driveType)
    {
        var ex = Assert.Throws<UnauthorizedAccessException>(() => WindowsKeyFileChecks.VerifyPathForm(KeyFile, driveType));
        Assert.Contains($"{driveType} drive", ex.Message);
    }

    [WindowsTheory]
    [InlineData(@"\\?\C:\HkdfGuardKeys\myapp\v1.key")]
    [InlineData(@"\\?\c:\hkdfguardkeys\MYAPP\v1.KEY")]
    public void VerifyFinalPath_SamePath_Passes(string finalPath)
        => WindowsKeyFileChecks.VerifyFinalPath(KeyFile, finalPath);

    [WindowsTheory]
    [InlineData(@"\\?\D:\elsewhere\v1.key")]         // a junction or symbolic link on the path
    [InlineData(@"\\?\C:\real\HkdfGuardKeys\myapp\v1.key")] // a substituted drive
    [InlineData(@"\\?\UNC\server\share\myapp\v1.key")] // a mapped network drive
    [InlineData(@"C:\HkdfGuardKeys\myapp\v1.key")]   // not the form GetFinalPathNameByHandle returns
    public void VerifyFinalPath_ElsewhereOrRemote_IsRefused(string finalPath)
    {
        var ex = Assert.Throws<UnauthorizedAccessException>(() => WindowsKeyFileChecks.VerifyFinalPath(KeyFile, finalPath));
        Assert.Contains(finalPath, ex.Message);
    }

    [WindowsFact]
    public void VerifyFinalPath_ShortNameRequested_IsRefused()
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyFinalPath(@"C:\PROGRA~1\HkdfGuard\v1.key", @"\\?\C:\Program Files\HkdfGuard\v1.key"));
    }

    [WindowsFact]
    public void VerifyNotReparsePoint_RealFolder_Passes()
        => WindowsKeyFileChecks.VerifyNotReparsePoint(FileAttributes.Directory, KeyFile, @"C:\HkdfGuardKeys");

    [WindowsFact]
    public void VerifyNotReparsePoint_JunctionOrLink_IsRefused()
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyNotReparsePoint(FileAttributes.Directory | FileAttributes.ReparsePoint, KeyFile, @"C:\HkdfGuardKeys"));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_TrustedOwnerAndReadOnlyForEveryoneElse_Passes()
        => WindowsKeyFileChecks.VerifyTrustedOnly(Locked(Administrators), KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted());

    [WindowsFact]
    public void VerifyTrustedOnly_UntrustedOwner_IsRefused()
    {
        var ex = Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(Locked(Users), KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
        Assert.Contains("is owned by", ex.Message);
    }

    [WindowsFact]
    public void VerifyTrustedOnly_NoOwner_IsRefused()
    {
        var ex = Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(new FileSecurity(), KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
        Assert.Contains("an unknown principal", ex.Message);
    }

    [WindowsTheory]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.WriteExtendedAttributes)]
    [InlineData(FileSystemRights.DeleteSubdirectoriesAndFiles)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    [InlineData(FileSystemRights.Modify)]
    [InlineData(FileSystemRights.FullControl)]
    public void VerifyTrustedOnly_AnyWriteRightForAnUntrustedPrincipal_IsRefused(FileSystemRights rights)
    {
        var security = Locked(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(Users, rights, AccessControlType.Allow));

        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
    }

    [WindowsTheory]
    [InlineData("GA")] // GENERIC_ALL
    [InlineData("GW")] // GENERIC_WRITE
    public void VerifyTrustedOnly_UnmappedGenericRights_AreRefused(string right)
    {
        // FileSystemAccessRule won't take generic bits, but a real ACE can carry them unmapped.
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm($"O:BAD:(A;;FA;;;SY)(A;;{right};;;BU)");

        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_ATrustedDeployerMayOwnAndModify()
    {
        var security = Locked(Deployers);
        security.AddAccessRule(new FileSystemAccessRule(Deployers, FileSystemRights.Modify, AccessControlType.Allow));

        WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted(Deployers.Value));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_IgnoresDenyAndInheritOnlyEntries()
    {
        // A folder's: only a folder carries entries meant for what's created inside it.
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));

        WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, @"C:\HkdfGuardKeys", WindowsKeyFileChecks.GuardedRights, Trusted());
    }

    [WindowsFact]
    public void VerifyTrustedOnly_DriveRoot_AllowsCreatingFoldersButNotRenamingThem()
    {
        // A default C:\: Authenticated Users may create folders (AppendData) in the root itself.
        var root = Locked(TrustedInstaller);
        root.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, FileSystemRights.AppendData, AccessControlType.Allow));
        WindowsKeyFileChecks.VerifyTrustedOnly(root, KeyFile, @"C:\", WindowsKeyFileChecks.GuardedRootRights, Trusted());

        // The same entry on any folder below the root is refused: they could create files there.
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(root, KeyFile, @"C:\HkdfGuardKeys", WindowsKeyFileChecks.GuardedRights, Trusted()));

        root.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsers, FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(root, KeyFile, @"C:\", WindowsKeyFileChecks.GuardedRootRights, Trusted()));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_DescribesAnUnmappableSidByItsValue()
    {
        var security = Locked(Administrators);
        security.AddAccessRule(new FileSystemAccessRule(Deployers, FileSystemRights.Write, AccessControlType.Allow));

        var ex = Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsKeyFileChecks.VerifyTrustedOnly(security, KeyFile, KeyFile, WindowsKeyFileChecks.GuardedRights, Trusted()));
        Assert.Contains(Deployers.Value, ex.Message);
    }
}
