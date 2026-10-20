using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// The macOS loader's system-call layer (MacOsNative) against the real filesystem and Security
/// framework, and the installed libhkdfguard.dylib and hkdfguard where they are
/// present. Skipped off macOS; the installed-library tests are skipped without the library.
/// MacOsNativeLibraryLoaderTests check the same decisions against a simulated filesystem on every
/// platform.
/// </summary>
[SupportedOSPlatform("macos")]
public partial class MacOsNativeIntegrationTests
{
    private const int ENOENT = 2;

    // --- The loader against the real system ------------------------------------------------------

    [InstalledMacOsLibraryFact]
    public void TheInstalledLibrary_PassesEveryCheck()
    {
        var (path, isSystem) = MacOsTestEnvironment.InstalledLibrary!.Value;
        uint[] owners = isSystem ? [0] : [0, MacOsNative.GetEffectiveUserId()];

        MacOsNativeLibraryLoader.VerifyLocation(path, MacOsNative.GetStatus, owners);
        MacOsNativeLibraryLoader.VerifySignature(path, MacOsNative.CheckCodeSignature);
    }

    private const string SystemProvisioningTool = $"{MacOsNativeLibraryLoader.SystemDirectory}/{MacOsTestEnvironment.ProvisioningToolName}";

    [MacOsFact(NeedsFile = SystemProvisioningTool)]
    public void TheProvisioningTool_IsSignedByTheTeam_ButRefused()
    {
        // Installed beside the library and signed by the same team: only the identifier in the
        // code requirement tells them apart.
        var tool = SystemProvisioningTool;

        var ex = Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifySignature(tool, MacOsNative.CheckCodeSignature));

        Assert.Contains(MacOsNativeLibraryLoader.TeamId, ex.Message);
    }

    [MacOsFact]
    public void AnUnsignedFile_IsRefused()
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-unsigned-");
        try
        {
            var path = Path.Combine(directory.FullName, MacOsNativeLibraryLoader.FileName);
            File.WriteAllBytes(path, [0xCF, 0xFA, 0xED, 0xFE]); // a Mach-O 64-bit magic, and nothing else

            Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifySignature(path, MacOsNative.CheckCodeSignature));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [MacOsFact]
    public void AUserWritableTemporaryDirectory_FailsTheLocationCheck()
    {
        // The planting scenario: a correctly named file somewhere the system install check would
        // refuse. The temp directory is owned by this user, never root, so a system-owner check fails.
        var directory = Directory.CreateTempSubdirectory("hkdfguard-plant-");
        try
        {
            var path = Path.Combine(directory.FullName, MacOsNativeLibraryLoader.FileName);
            File.WriteAllBytes(path, []);
            var resolved = RealPath(path); // /var -> /private/var

            var ex = Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifyLocation(resolved, MacOsNative.GetStatus, [0]));

            Assert.Contains("owned by uid", ex.Message);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [MacOsFact]
    public void ProbeDistinguishesMissingFromPresent()
    {
        Assert.Equal(0, MacOsNative.Probe("/"));
        Assert.Equal(ENOENT, MacOsNative.Probe("/definitely/not/here"));
    }

    [InstalledMacOsLibraryFact]
    public void TheInstalledLibrary_LoadsOnce_AndAnswersCalls()
    {
        var first = MacOsNativeLibraryLoader.Load();
        Assert.NotEqual(IntPtr.Zero, first);
        Assert.Equal(first, MacOsNativeLibraryLoader.Load());

        // Through the binding (and so the resolver). No KEK is provisioned for this name, so the
        // library answers with an error status - which proves it loaded and ran. Bounded, like
        // every first native call here, so an unanswered keychain dialog fails rather than hangs.
        var library = new MacOsHkdfGuardKmsLibrary();
        var service = NativeTestEnvironment.UnprovisionedServiceName;
        var status = NativeTestEnvironment.WithinNativeCallTimeout(service, () =>
            library.WrapDek(service, new byte[AbstractHkdfGuardKmsLibrary.DekLength], new byte[512], out _));

        Assert.True(status < 0, $"wrap under an unprovisioned service returned status {status}");
        Assert.NotNull(library.DescribeStatus(status));
    }

    // --- The test service ------------------------------------------------------------------------

    [InstalledMacOsLibraryFact(NeedsProvisioningTool = true)]
    public void TheProvisioningTool_ReportsAnUnprovisionedService_AsAbsent()
    {
        var (exitCode, output) = MacOsTestEnvironment.Run(MacOsTestEnvironment.ProvisioningTool!, "status", "--service-name", NativeTestEnvironment.UnprovisionedServiceName);

        Assert.True(exitCode == 0 && output.Contains("kek: absent", StringComparison.Ordinal), $"status exited {exitCode}: {output}");
    }

    [InstalledMacOsLibraryFact(NeedsProvisioningTool = true)]
    public void TheDefaultTestService_IsFoundOnlyWhenProvisioned()
    {
        var (exitCode, output) = MacOsTestEnvironment.Run(MacOsTestEnvironment.ProvisioningTool!, "status", "--service-name", NativeTestEnvironment.DefaultServiceName);
        Assert.True(exitCode == 0, $"status exited {exitCode}: {output}");

        var (service, skipReason) = NativeTestEnvironment.ResolveMacOs();

        var provisioned = output.Contains("kek: present", StringComparison.Ordinal);
        Assert.True(service is not null == provisioned, $"environment = ({service}, {skipReason}), but the tool reports provisioned = {provisioned}");
    }

    private static string RealPath(string path)
    {
        var resolved = realpath(path, IntPtr.Zero);
        Assert.NotEqual(IntPtr.Zero, resolved);
        try
        {
            return Marshal.PtrToStringUTF8(resolved)!;
        }
        finally
        {
            free(resolved);
        }
    }

    [LibraryImport("/usr/lib/libSystem.B.dylib", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr realpath(string path, IntPtr resolvedPath);

    [LibraryImport("/usr/lib/libSystem.B.dylib")]
    private static partial void free(IntPtr pointer);
}
