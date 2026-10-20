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
public partial class LinuxNativeLibraryLoaderSystemTests
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
    public void TheRootAndSystemLibraryDirectories_AreTrusted()
    {
        foreach (var directory in new[] { "/", "/usr/lib" })
            Assert.Equal(directory, Resolve(directory, UnixFileType.Directory));
    }

    [LinuxFact]
    public void ProbeDistinguishesMissingFromPresent()
    {
        Assert.Equal(0, LinuxNative.Probe("/"));
        Assert.Equal(ENOENT, LinuxNative.Probe("/definitely/not/here"));
    }

    [LinuxFact]
    public void StatusAndReadLink_DescribeThisUsersFiles()
    {
        var directory = Directory.CreateTempSubdirectory("hkdfguard-status-");
        try
        {
            var file = Path.Combine(directory.FullName, "file");
            var link = Path.Combine(directory.FullName, "link");
            File.WriteAllBytes(file, "x"u8.ToArray());
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            File.CreateSymbolicLink(link, "file");

            var status = LinuxNative.GetStatusOrNull(file);
            Assert.NotNull(status);
            Assert.Equal(UnixFileType.RegularFile, status.Value.Type);
            Assert.Equal(getuid(), status.Value.OwnerId);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead, status.Value.Permissions & (UnixFileMode)0x1FF);

            var linkStatus = LinuxNative.GetStatusOrNull(link);
            Assert.NotNull(linkStatus);
            Assert.Equal(UnixFileType.SymbolicLink, linkStatus.Value.Type); // the link itself, not its target
            Assert.Equal(getuid(), linkStatus.Value.OwnerId);
            Assert.Equal("file", LinuxNative.ReadLink(link));

            Assert.Null(LinuxNative.GetStatusOrNull(Path.Combine(directory.FullName, "missing")));

            // Owned by this user (or, as root, in a world-writable temp directory), so the loader
            // refuses it - however it is reached.
            Assert.Throws<SecurityException>(() => Resolve(file));
            Assert.Throws<SecurityException>(() => Resolve(link));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [LinuxFact]
    public void ThisProcesssLibc_PassesTheLoadedImageAndDependencyChecks()
    {
        // The post-load checks (dladdr, DT_NEEDED parsing, dlopen(RTLD_NOLOAD) + dlinfo, the path
        // checks) against a real loaded library, so they run on any Linux host, package or not.
        var loaded = LinuxNative.GetLoadedPath("libc.so.6");
        Assert.NotNull(loaded);
        var libc = Resolve(loaded)!;

        var handle = NativeLibrary.Load(libc);
        try
        {
            // dladdr places a libc export in libc.
            var image = LinuxNative.GetImagePath(NativeLibrary.GetExport(handle, "getpid"));
            Assert.NotNull(image);
            LinuxNativeLibraryLoader.VerifyLoadedImage(libc, Resolve(image));
            Assert.Null(LinuxNative.GetImagePath(IntPtr.Zero));

            Assert.Contains(ElfDependencies.ReadNeeded(libc), name => name.StartsWith("ld-linux", StringComparison.Ordinal));
            LinuxNativeLibraryLoader.VerifyDependencies(libc, ElfDependencies.ReadNeeded, LinuxNative.GetLoadedPath, p => Resolve(p)!);
        }
        finally
        {
            NativeLibrary.Free(handle);
        }
    }

    [UninstalledLinuxLibraryFact]
    public void WithoutThePackage_LoadingReportsItIsNotInstalled()
    {
        // Where the package is absent, the real loader must say so, naming the package, rather
        // than fall back to any search.
        var ex = Assert.Throws<DllNotFoundException>(() => LinuxNativeLibraryLoader.Load());
        Assert.Contains("libhkdfguard1", ex.Message);

        // And so must the binding, through the resolver.
        Assert.Throws<DllNotFoundException>(() => new LinuxHkdfGuardKmsLibrary().WrapDek("hkdfguard.loadertest.unprovisioned", new byte[32], new byte[512], out _));
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
    public void TheInstalledLibrary_IsInATrustedLocation()
    {
        var path = InstalledLinuxLibraryFactAttribute.InstalledPath!;

        Assert.Equal(path, Resolve(path));
    }

    [InstalledLinuxLibraryFact]
    public void TheInstalledLibrary_LoadsThroughTheVerifiedLoader_AnswersTheBinding_AndItsDependenciesAreTrusted()
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

        // What the dynamic linker mapped is the verified file, and every dependency it pulled in
        // came from a trusted file.
        Assert.True(NativeLibrary.TryGetExport(handle, LinuxNativeLibraryLoader.ProbeExport, out var export));
        Assert.Equal(InstalledLinuxLibraryFactAttribute.InstalledPath, Resolve(LinuxNative.GetImagePath(export)!));
        LinuxNativeLibraryLoader.VerifyDependencies(InstalledLinuxLibraryFactAttribute.InstalledPath!, ElfDependencies.ReadNeeded, LinuxNative.GetLoadedPath, p => Resolve(p)!);
    }

    private const int ENOENT = 2;

    [LibraryImport("libc.so.6")]
    private static partial uint getuid();
}
