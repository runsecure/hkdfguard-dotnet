using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// The Linux loader's checks against this machine's real filesystem and dynamic linker, and the
/// installed libhkdfguard1 package where there is one. Skipped off Linux.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxNativeLibraryLoaderSystemTests
{
    private static string? Resolve(string path, UnixFileType type = UnixFileType.RegularFile, bool allowMissing = false)
        => LinuxNativeLibraryLoader.ResolveTrusted(path, type, LinuxNative.GetStatusOrNull, LinuxNative.ReadLink, allowMissing);

    [LinuxFact]
    public void TheRootDirectory_AndThisProcesssLibc_AreTrusted()
    {
        Assert.Equal("/", Resolve("/", UnixFileType.Directory));

        var libc = LinuxNative.GetLoadedPath("libc.so.6");
        Assert.NotNull(libc);
        Assert.StartsWith("/", Resolve(libc));
    }

    [LinuxFact]
    public void ANameNothingIsLoadedUnder_HasNoLoadedPath()
        => Assert.Null(LinuxNative.GetLoadedPath("libhkdfguard-never-loaded.so.0"));

    [LinuxFact]
    public void ADirectoryThisUserCreated_IsNotTrusted_ForTheLibraryPath()
    {
        // The attack this loader exists to stop: a directory the service's own user (or anyone)
        // can write, put on LD_LIBRARY_PATH so a dependency is found there first.
        var directory = Directory.CreateTempSubdirectory("hkdfguard-ldpath-");
        try
        {
            var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyEnvironment(
                new Dictionary<string, IReadOnlyList<string>> { ["LD_LIBRARY_PATH"] = [directory.FullName] },
                (p, type) => Resolve(p, type, allowMissing: true)));

            Assert.Contains(directory.FullName, ex.Message);
        }
        finally
        {
            directory.Delete();
        }
    }

    [LinuxFact]
    public void TheLinkersVariables_AreReadFromProcEnviron()
    {
        // Whatever this process started with, /proc/self/environ must be readable for the loader
        // to see it - and parse to the same three variables.
        var block = LinuxNative.ReadInitialEnvironment();
        Assert.NotNull(block);

        var values = LinuxNativeLibraryLoader.ReadEnvironment(_ => null, block);
        Assert.Equal(["LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"], values.Keys.Order());
    }

    [InstalledLinuxLibraryFact]
    public void TheInstalledLibrary_IsAKnownReleaseInATrustedLocation()
    {
        var path = InstalledLinuxLibraryFactAttribute.InstalledPath!;

        Assert.Equal(path, Resolve(path));
        LinuxNativeLibraryLoader.VerifyContent(path, p => Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(p))), LinuxNativeLibraryLoader.KnownReleases);
    }

    [InstalledLinuxLibraryFact]
    public void TheInstalledLibrary_LoadsThroughTheVerifiedLoader_AndAnswersTheBinding()
    {
        var handle = LinuxNativeLibraryLoader.Load();
        Assert.NotEqual(IntPtr.Zero, handle);
        Assert.Equal(handle, LinuxNativeLibraryLoader.Load()); // once per process

        // Through the binding (and so the resolver): a wrap for a service nobody provisioned.
        // Whatever this host's providers say, the answer is a status code the binding can
        // describe - never a DllNotFoundException from the default search.
        var library = new LinuxHkdfGuardKmsLibrary();
        var status = library.WrapDek("hkdfguard.loadertest.unprovisioned", new byte[32], new byte[512], out _);
        Assert.True(status == AbstractHkdfGuardKmsLibrary.Ok || library.DescribeStatus(status) is not null, $"undescribed status {status}");

        // And every dependency it pulled in came from a trusted file.
        Assert.True(NativeLibrary.TryGetExport(handle, LinuxNativeLibraryLoader.ProbeExport, out var export));
        Assert.Equal(InstalledLinuxLibraryFactAttribute.InstalledPath, Resolve(LinuxNative.GetImagePath(export)!));
    }
}
