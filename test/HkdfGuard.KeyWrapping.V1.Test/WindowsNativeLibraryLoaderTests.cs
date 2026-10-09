using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

[SupportedOSPlatform("windows")]
public class WindowsNativeLibraryLoaderTests
{
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    [WindowsFact]
    public void InstalledPath_IsTheFixedProgramFilesLocation()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        Assert.Equal(Path.Combine(programFiles, "HkdfGuard", "v1", "HkdfGuardV1.dll"), WindowsNativeLibraryLoader.InstalledPath);
    }

    [WindowsFact]
    public void Load_WhenTheFileIsMissing_ThrowsDllNotFound_NamingTheOnlySupportedPath()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"hkdfguard-missing-{Guid.NewGuid():N}", "HkdfGuardV1.dll");

        var ex = Assert.Throws<DllNotFoundException>(() => WindowsNativeLibraryLoader.Load(missing, WindowsNativeLibraryLoader.ExpectedPublisher));

        Assert.Contains(missing, ex.Message);
    }

    [WindowsFact]
    public void Load_FromAUserWritableFolder_IsRefused_BeforeAnythingIsLoaded()
    {
        // The DLL-planting scenario: a correctly named file in a folder the current user controls.
        var dir = Directory.CreateTempSubdirectory("hkdfguard-plant-");
        try
        {
            var planted = Path.Combine(dir.FullName, WindowsNativeLibraryLoader.FileName);
            File.WriteAllBytes(planted, [0x4D, 0x5A]);

            Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.Load(planted, WindowsNativeLibraryLoader.ExpectedPublisher));
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [WindowsFact]
    public void VerifyTrustedOnly_TrustedOwnerAndReadOnlyForEveryoneElse_Passes()
    {
        var security = Security(owner: System,
            (System, FileSystemRights.FullControl),
            (Administrators, FileSystemRights.FullControl),
            (TrustedInstaller, FileSystemRights.FullControl),
            (Users, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize));

        WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test");
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
    public void VerifyTrustedOnly_AnyWriteRightForAnUntrustedPrincipal_IsRefused(FileSystemRights right)
    {
        var security = Security(owner: Administrators, (Users, right));

        var ex = Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test"));

        Assert.Contains(Users.Value, ex.Message);
    }

    [WindowsTheory]
    [InlineData("GA")] // GENERIC_ALL
    [InlineData("GW")] // GENERIC_WRITE
    public void VerifyTrustedOnly_UnmappedGenericWriteForAnUntrustedPrincipal_IsRefused(string genericRight)
    {
        // FileSystemAccessRule won't construct generic rights, but a real descriptor can hold them.
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm($"O:SYD:(A;;FA;;;SY)(A;;{genericRight};;;AU)");

        Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test"));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_AnUntrustedOwner_IsRefused()
    {
        // An owner can always rewrite the ACL, whatever it currently says.
        var security = Security(owner: Users, (System, FileSystemRights.FullControl));

        Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test"));
    }

    [WindowsFact]
    public void VerifyTrustedOnly_NoOwnerAtAll_IsRefused()
    {
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm("D:(A;;FA;;;SY)");

        var ex = Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test"));

        Assert.Contains("an unknown principal", ex.Message);
    }

    [WindowsFact]
    public void VerifyTrustedOnly_AnOwnerSidWithNoAccount_IsRefused_AndNamedBySid()
    {
        // A SID that maps to no account here, e.g. left behind by a deleted user.
        var orphan = new SecurityIdentifier("S-1-5-21-1-2-3-4242");
        var security = Security(owner: orphan, (System, FileSystemRights.FullControl));

        var ex = Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test"));

        Assert.Contains(orphan.Value, ex.Message);
    }

    [WindowsFact]
    public void VerifyTrustedOnly_InheritOnlyAndDenyEntries_AreIgnored()
    {
        // A folder like Program Files: Users get full control of what they create beneath it
        // (inherit-only, so not of the folder itself), plus an explicit Deny.
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm("O:SYD:(D;;FW;;;BU)(A;;FA;;;SY)(A;OICIIO;FA;;;BU)(A;;FR;;;BU)");

        WindowsNativeLibraryLoader.VerifyTrustedOnly(security, "test");
    }

    [WindowsFact]
    public void VerifyNotReparsePoint_AJunction_IsRefused()
    {
        // Junctions need no privilege to create, unlike symbolic links.
        var target = Directory.CreateTempSubdirectory("hkdfguard-target-");
        var junction = Path.Combine(Path.GetTempPath(), $"hkdfguard-junction-{Guid.NewGuid():N}");
        try
        {
            using (var mklink = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{junction}\" \"{target.FullName}\"")
                   { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!)
            {
                mklink.WaitForExit();
                Assert.Equal(0, mklink.ExitCode);
            }

            Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifyNotReparsePoint(new DirectoryInfo(junction)));
            WindowsNativeLibraryLoader.VerifyNotReparsePoint(target);
        }
        finally
        {
            Directory.Delete(junction);
            target.Delete();
        }
    }

    [WindowsFact]
    public void VerifySignature_AnUnsignedFile_IsRefused()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00]);

            Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifySignature(path, WindowsNativeLibraryLoader.ExpectedPublisher));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [InstalledWindowsLibraryFact]
    public void VerifyLocation_TheInstalledLibrary_Passes()
    {
        WindowsNativeLibraryLoader.VerifyLocation(WindowsNativeLibraryLoader.InstalledPath);
    }

    [InstalledWindowsLibraryFact]
    public void VerifySignature_TheInstalledLibrary_IsValidAndFromTheExpectedPublisher()
    {
        WindowsNativeLibraryLoader.VerifySignature(WindowsNativeLibraryLoader.InstalledPath, WindowsNativeLibraryLoader.ExpectedPublisher);
    }

    [InstalledWindowsLibraryFact]
    public void VerifySignature_ValidButFromAnotherPublisher_IsRefused()
    {
        var ex = Assert.Throws<SecurityException>(() =>
            WindowsNativeLibraryLoader.VerifySignature(WindowsNativeLibraryLoader.InstalledPath, "CN=Someone Else"));

        Assert.Contains("not the expected HkdfGuard publisher", ex.Message);
    }

    [InstalledWindowsLibraryFact]
    public void VerifySignature_ATamperedCopy_IsRefused()
    {
        var copy = Path.GetTempFileName();
        try
        {
            var bytes = File.ReadAllBytes(WindowsNativeLibraryLoader.InstalledPath);
            bytes[bytes.Length / 2] ^= 0xFF; // inside the signed image, not the signature itself
            File.WriteAllBytes(copy, bytes);

            Assert.Throws<SecurityException>(() => WindowsNativeLibraryLoader.VerifySignature(copy, WindowsNativeLibraryLoader.ExpectedPublisher));
        }
        finally
        {
            File.Delete(copy);
        }
    }

    [InstalledWindowsLibraryFact]
    public void Load_TheInstalledLibrary_ReturnsTheSameHandleEveryTime()
    {
        var first = WindowsNativeLibraryLoader.Load();
        var second = WindowsNativeLibraryLoader.Load();

        Assert.NotEqual(IntPtr.Zero, first);
        Assert.Equal(first, second);
    }

    [InstalledWindowsLibraryFact]
    public void Resolver_MapsTheWindowsLibraryToTheVerifiedInstall_AndLeavesEverythingElseToTheDefault()
    {
        var assembly = typeof(NativeLibraryResolver).Assembly;

        Assert.Equal(WindowsNativeLibraryLoader.Load(),
            NativeLibraryResolver.Resolve(WindowsHkdfGuardKmsLibrary.LibraryName, assembly, null));
        Assert.Equal(IntPtr.Zero, NativeLibraryResolver.Resolve("wintrust.dll", assembly, null));
    }

    [InstalledWindowsLibraryFact]
    public void TheWindowsBinding_CallsIntoTheInstalledLibrary()
    {
        // A real native round trip through the resolver. No KEK is provisioned for this name, so
        // the library answers with an error status - which proves it loaded and ran.
        var library = new WindowsHkdfGuardKmsLibrary();

        var status = library.WrapDek(NativeTestEnvironment.UnprovisionedServiceName, new byte[32], new byte[512], out _);

        Assert.True(status < 0);
    }

    private static FileSecurity Security(SecurityIdentifier owner, params (SecurityIdentifier Who, FileSystemRights Rights)[] allows)
    {
        var security = new FileSecurity();
        security.SetOwner(owner);
        foreach (var (who, rights) in allows)
            security.AddAccessRule(new FileSystemAccessRule(who, rights, AccessControlType.Allow));
        return security;
    }
}
