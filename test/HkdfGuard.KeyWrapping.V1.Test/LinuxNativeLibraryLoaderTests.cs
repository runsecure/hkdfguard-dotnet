using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// The Linux loader's decisions - where the library is, whether every path to it and to its
/// dependencies can be trusted, whether it is a known release, and whether the dynamic linker's
/// environment could substitute anything - checked against simulated filesystems, so they run on
/// every platform. LinuxNativeLibraryLoaderSystemTests runs the same checks against the real
/// filesystem and the installed package.
/// </summary>
public class LinuxNativeLibraryLoaderTests
{
    private const uint Root = 0;
    private const uint User = 1000;

    private const UnixFileMode Mode755 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                         | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                         | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    private const UnixFileMode Mode775 = Mode755 | UnixFileMode.GroupWrite;
    private const UnixFileMode Mode1777 = Mode755 | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite | UnixFileMode.StickyBit;
    private const UnixFileMode Mode644 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    private const UnixFileMode Mode664 = Mode644 | UnixFileMode.GroupWrite;
    private const UnixFileMode Mode777 = Mode755 | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    private const string LibDir = "/usr/lib/x86_64-linux-gnu";
    private const string Library = $"{LibDir}/libhkdfguard.so.1";
    private const string Esys = $"{LibDir}/libtss2-esys.so.0.0.1";

    /// <summary>A simulated filesystem: what lstat sees, and what each symbolic link holds.</summary>
    private sealed class FileSystem
    {
        public Dictionary<string, UnixFileStatus> Entries { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Links { get; } = new(StringComparer.Ordinal);

        public FileSystem Dir(string path, uint owner = Root, UnixFileMode mode = Mode755)
        {
            Entries[path] = new UnixFileStatus(owner, owner, mode, UnixFileType.Directory);
            return this;
        }

        public FileSystem File(string path, uint owner = Root, UnixFileMode mode = Mode644)
        {
            Entries[path] = new UnixFileStatus(owner, owner, mode, UnixFileType.RegularFile);
            return this;
        }

        public FileSystem Link(string path, string target, uint owner = Root)
        {
            Entries[path] = new UnixFileStatus(owner, owner, Mode777, UnixFileType.SymbolicLink);
            Links[path] = target;
            return this;
        }

        public UnixFileStatus? Status(string path) => Entries.TryGetValue(path, out var status) ? status : null;

        public string? ReadLink(string path) => Links.GetValueOrDefault(path);

        public string? Resolve(string path, UnixFileType type = UnixFileType.RegularFile, bool allowMissing = false)
            => LinuxNativeLibraryLoader.ResolveTrusted(path, type, Status, ReadLink, allowMissing);
    }

    // A standard Debian/Ubuntu host with merged /usr: /lib is a root-owned link to usr/lib.
    private static FileSystem StandardHost() => new FileSystem()
        .Dir("/").Dir("/usr").Dir("/usr/lib").Dir(LibDir).Dir("/usr/lib64").Dir("/opt")
        .Link("/lib", "usr/lib")
        .Link("/lib64", "usr/lib64")
        .File(Library)
        .Link($"{LibDir}/HkdfGuard.Kms.Linux.v1.so", "libhkdfguard.so.1")
        .Link($"{LibDir}/libtss2-esys.so.0", "libtss2-esys.so.0.0.1")
        .File(Esys)
        .File($"{LibDir}/libc.so.6")
        .Dir("/home").Dir("/home/dev", User).Dir("/home/dev/lib", User).File("/home/dev/lib/libtss2-esys.so.0", User)
        .Dir("/tmp", Root, Mode1777);

    // --- Platform and location ------------------------------------------------------------------

    [Fact]
    public void CandidatePaths_AreThePackagesInstallLocations_ForEachArchitecture()
    {
        Assert.Equal(["/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"], LinuxNativeLibraryLoader.CandidatePaths(Architecture.X64));
        Assert.Equal(["/usr/lib/aarch64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"], LinuxNativeLibraryLoader.CandidatePaths(Architecture.Arm64));
    }

    [Theory]
    [InlineData(Architecture.X86)]
    [InlineData(Architecture.Arm)]
    [InlineData(Architecture.RiscV64)]
    public void CandidatePaths_RefuseEveryOtherArchitecture(Architecture architecture)
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(() => LinuxNativeLibraryLoader.CandidatePaths(architecture));

        Assert.Contains(architecture.ToString(), ex.Message);
    }

    private const int Present = 0;
    private const int ENOENT = 2;
    private const int EACCES = 13;
    private const int ENOTDIR = 20;

    private static readonly string[] Candidates = LinuxNativeLibraryLoader.CandidatePaths(Architecture.X64);

    [Fact]
    public void ChoosePath_PrefersTheMultiarchDirectory()
        => Assert.Equal(Candidates[0], LinuxNativeLibraryLoader.ChoosePath(Candidates, _ => Present));

    [Theory]
    [InlineData(ENOENT)]
    [InlineData(ENOTDIR)]
    public void ChoosePath_UsesLib64_OnlyWhenThereIsNothingInTheMultiarchDirectory(int errno)
        => Assert.Equal(Candidates[1], LinuxNativeLibraryLoader.ChoosePath(Candidates, p => p == Candidates[0] ? errno : Present));

    [Fact]
    public void ChoosePath_WhenALocationCannotBeExamined_RefusesInsteadOfFallingBack()
    {
        var asked = new List<string>();
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.ChoosePath(Candidates, p =>
        {
            asked.Add(p);
            return EACCES;
        }));

        Assert.Equal([Candidates[0]], asked);
        Assert.Contains("errno 13", ex.Message);
    }

    [Fact]
    public void ChoosePath_WithNothingInstalled_ThrowsNamingThePackageAndEveryLocation()
    {
        var ex = Assert.Throws<DllNotFoundException>(() => LinuxNativeLibraryLoader.ChoosePath(Candidates, _ => ENOENT));

        Assert.Contains("libhkdfguard1", ex.Message);
        Assert.Contains(Candidates[0], ex.Message);
        Assert.Contains(Candidates[1], ex.Message);
    }

    // --- Path integrity -------------------------------------------------------------------------

    [Fact]
    public void AStandardInstall_ResolvesToItself()
        => Assert.Equal(Library, StandardHost().Resolve(Library));

    [Fact]
    public void ARootOwnedLink_IsFollowed_AndItsTargetChecked()
    {
        var fs = StandardHost();

        Assert.Equal(Esys, fs.Resolve("/lib/x86_64-linux-gnu/libtss2-esys.so.0"));
        Assert.Equal(Library, fs.Resolve($"{LibDir}/HkdfGuard.Kms.Linux.v1.so"));
        Assert.Equal(LibDir, fs.Resolve("/lib/x86_64-linux-gnu/", UnixFileType.Directory));
    }

    [Fact]
    public void DotDot_IsResolvedAgainstTheRealDirectory_NotTheLinkThatLedThere()
    {
        // /opt/app -> ../usr/lib: "/opt/app/.." is /usr, not /opt.
        var fs = StandardHost().Link("/opt/app", "../usr/lib");

        Assert.Equal(Library, fs.Resolve("/opt/app/x86_64-linux-gnu/libhkdfguard.so.1"));
        Assert.Equal("/usr", fs.Resolve("/opt/app/..", UnixFileType.Directory));
        Assert.Equal("/", fs.Resolve("/..", UnixFileType.Directory));
        Assert.Equal(Library, fs.Resolve("/usr/./lib/x86_64-linux-gnu//libhkdfguard.so.1"));
    }

    [Theory]
    [InlineData("usr/lib/x86_64-linux-gnu/libhkdfguard.so.1")]
    [InlineData("./libhkdfguard.so.1")]
    [InlineData("")]
    public void ARelativePath_IsRefused(string path)
    {
        var ex = Assert.Throws<SecurityException>(() => StandardHost().Resolve(path));

        Assert.Contains("not an absolute path", ex.Message);
    }

    [Fact]
    public void AFileOwnedByAUser_IsRefused()
    {
        var fs = StandardHost().File(Library, User);

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve(Library));
        Assert.Contains("uid 1000", ex.Message);
    }

    [Fact]
    public void ADirectoryOwnedByAUser_IsRefused_WhereverItIsOnThePath()
    {
        var fs = StandardHost().Dir("/usr/lib", User);

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve(Library));
        Assert.Contains("'/usr/lib'", ex.Message);
    }

    [Theory]
    [InlineData("/", Mode775)]
    [InlineData("/usr", Mode775)]
    [InlineData(LibDir, Mode775)]
    [InlineData(LibDir, Mode777)]
    [InlineData(Library, Mode664)]
    public void AnythingWritableByGroupOrOthers_IsRefused_EvenWhenRootOwned(string path, UnixFileMode mode)
    {
        var fs = StandardHost();
        fs.Entries[path] = fs.Entries[path] with { Permissions = mode };

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve(Library));
        Assert.Contains($"'{path}' is writable", ex.Message);
    }

    [Fact]
    public void AStickyWorldWritableDirectory_IsRefused()
    {
        var fs = StandardHost().File("/tmp/libtss2-esys.so.0");

        Assert.Throws<SecurityException>(() => fs.Resolve("/tmp/libtss2-esys.so.0"));
    }

    [Fact]
    public void ALinkOwnedByAUser_IsRefused_EvenWhenItPointsSomewhereTrusted()
    {
        var fs = StandardHost().Link("/opt/lib", "/usr/lib", User);

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve("/opt/lib/x86_64-linux-gnu/libhkdfguard.so.1"));
        Assert.Contains("symbolic link owned by uid 1000", ex.Message);
    }

    [Fact]
    public void ARootOwnedLink_IntoAUsersDirectory_IsRefused()
    {
        var fs = StandardHost().Link("/opt/lib", "/home/dev/lib");

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve("/opt/lib/libtss2-esys.so.0"));
        Assert.Contains("'/home/dev'", ex.Message);
    }

    [Fact]
    public void ALinkLoop_IsRefused()
    {
        var fs = StandardHost().Link("/opt/a", "/opt/b").Link("/opt/b", "/opt/a");

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve("/opt/a/x"));
        Assert.Contains($"{LinuxNativeLibraryLoader.MaxSymbolicLinks} symbolic links", ex.Message);
    }

    [Fact]
    public void ALinkThatCannotBeRead_IsRefused()
    {
        var fs = StandardHost();
        fs.Entries["/opt/broken"] = new UnixFileStatus(Root, Root, Mode777, UnixFileType.SymbolicLink);

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve("/opt/broken/x"));
        Assert.Contains("could not be read", ex.Message);
    }

    [Fact]
    public void AMissingPath_IsRefused_UnlessMissingIsAllowed()
    {
        var fs = StandardHost();

        var ex = Assert.Throws<SecurityException>(() => fs.Resolve($"{LibDir}/nothing.so"));
        Assert.Contains("does not exist", ex.Message);
        Assert.Null(fs.Resolve($"{LibDir}/nothing.so", allowMissing: true));
        Assert.Null(fs.Resolve("/opt/not/yet/created", UnixFileType.Directory, allowMissing: true));
    }

    [Fact]
    public void AMissingPath_UnderAnUntrustedDirectory_IsStillRefused()
    {
        // Something missing is only harmless if nobody but root could create it.
        var fs = StandardHost();

        Assert.Throws<SecurityException>(() => fs.Resolve("/home/dev/lib/nothing.so", allowMissing: true));
    }

    [Fact]
    public void TheWrongKindOfObject_IsRefused()
    {
        var fs = StandardHost();
        fs.Entries["/opt/fifo"] = new UnixFileStatus(Root, Root, Mode644, UnixFileType.Other);

        Assert.Contains("is a directory, not a regular file", Assert.Throws<SecurityException>(() => fs.Resolve(LibDir)).Message);
        Assert.Contains("is a regular file, not a directory", Assert.Throws<SecurityException>(() => fs.Resolve(Library, UnixFileType.Directory)).Message);
        Assert.Contains("is a special file", Assert.Throws<SecurityException>(() => fs.Resolve("/opt/fifo")).Message);
    }

    [Fact]
    public void APathThroughAFile_IsRefused()
    {
        var ex = Assert.Throws<SecurityException>(() => StandardHost().Resolve($"{Library}/x"));

        Assert.Contains("not a directory", ex.Message);
    }

    [Fact]
    public void AnUnexaminableRoot_IsRefused()
    {
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.ResolveTrusted(Library, UnixFileType.RegularFile, _ => null, _ => null));

        Assert.Contains("'/'", ex.Message);
    }

    [Theory]
    [InlineData("/", "/")]
    [InlineData("/usr", "/")]
    [InlineData("/usr/lib", "/usr")]
    public void ParentOf_WalksUpToRoot(string path, string parent)
        => Assert.Equal(parent, LinuxNativeLibraryLoader.ParentOf(path));

    // --- Content --------------------------------------------------------------------------------

    private static readonly Dictionary<string, string> Releases = new() { [new string('a', 64)] = "test release" };

    [Fact]
    public void VerifyContent_AcceptsAKnownRelease()
        => LinuxNativeLibraryLoader.VerifyContent(Library, _ => new string('a', 64), Releases);

    [Fact]
    public void VerifyContent_RefusesAnythingElse_NamingItsHash()
    {
        var other = new string('b', 64);
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyContent(Library, _ => other, Releases));

        Assert.Contains(other, ex.Message);
        Assert.Contains(Library, ex.Message);
    }

    [Fact]
    public void EveryKnownRelease_IsALowercaseSha256()
    {
        Assert.NotEmpty(LinuxNativeLibraryLoader.KnownReleases);
        foreach (var (hash, description) in LinuxNativeLibraryLoader.KnownReleases)
        {
            Assert.Matches("^[0-9a-f]{64}$", hash);
            Assert.False(string.IsNullOrWhiteSpace(description));
        }
    }

    // --- Environment ----------------------------------------------------------------------------

    private static byte[] EnvironBlock(params string[] entries) => Encoding.UTF8.GetBytes(string.Join('\0', entries) + '\0');

    [Fact]
    public void ReadEnvironment_CollectsTheInitialAndCurrentValues_OfTheLinkersVariablesOnly()
    {
        var current = new Dictionary<string, string> { ["LD_LIBRARY_PATH"] = "/now", ["LD_PRELOAD"] = "/same.so" };
        var values = LinuxNativeLibraryLoader.ReadEnvironment(
            current.GetValueOrDefault,
            EnvironBlock("PATH=/usr/bin", "LD_LIBRARY_PATH=/at/exec", "LD_PRELOAD=/same.so", "LD_AUDIT=/a.so=b", "=junk", "NOEQUALS"));

        Assert.Equal(["/at/exec", "/now"], values["LD_LIBRARY_PATH"]);
        Assert.Equal(["/same.so"], values["LD_PRELOAD"]);
        Assert.Equal(["/a.so=b"], values["LD_AUDIT"]);
        Assert.Equal(3, values.Count);
    }

    [Fact]
    public void ReadEnvironment_WithoutProcEnviron_UsesTheCurrentEnvironment()
    {
        var values = LinuxNativeLibraryLoader.ReadEnvironment(n => n == "LD_PRELOAD" ? "x.so" : null, null);

        Assert.Equal(["x.so"], values["LD_PRELOAD"]);
        Assert.Empty(values["LD_LIBRARY_PATH"]);
    }

    private static void VerifyEnvironment(FileSystem fs, string variable, params string[] values)
        => LinuxNativeLibraryLoader.VerifyEnvironment(
            new Dictionary<string, IReadOnlyList<string>> { [variable] = values },
            (p, type) => fs.Resolve(p, type, allowMissing: true));

    [Fact]
    public void AnUnsetEnvironment_Passes()
        => LinuxNativeLibraryLoader.VerifyEnvironment(new Dictionary<string, IReadOnlyList<string>>(), (_, _) => throw new InvalidOperationException("nothing to resolve"));

    [Theory]
    [InlineData("")]                                          // ignored by the dynamic linker
    [InlineData("/usr/lib/x86_64-linux-gnu")]
    [InlineData("/lib/x86_64-linux-gnu:/usr/lib64")]          // through root-owned links
    [InlineData("/usr/lib;/usr/lib64")]                        // ';' separates too
    [InlineData("/opt/not/installed/yet")]                     // missing, but only root could create it
    public void ALibraryPathOfRootControlledDirectories_Passes(string value)
        => VerifyEnvironment(StandardHost(), "LD_LIBRARY_PATH", value);

    [Theory]
    [InlineData("/home/dev/lib")]
    [InlineData("/usr/lib:/home/dev/lib")]
    [InlineData("/tmp")]
    [InlineData("/home/dev/lib/not-yet")]
    public void ALibraryPathWithADirectoryOthersCanWrite_IsRefused(string value)
    {
        var ex = Assert.Throws<SecurityException>(() => VerifyEnvironment(StandardHost(), "LD_LIBRARY_PATH", value));

        Assert.Contains("LD_LIBRARY_PATH", ex.Message);
        Assert.Contains("Remove it", ex.Message);
    }

    [Theory]
    [InlineData(":/usr/lib")]
    [InlineData("/usr/lib:")]
    [InlineData("/usr/lib::/usr/lib64")]
    public void ALibraryPathWithAnEmptyEntry_IsRefused_AsTheWorkingDirectory(string value)
    {
        var ex = Assert.Throws<SecurityException>(() => VerifyEnvironment(StandardHost(), "LD_LIBRARY_PATH", value));

        Assert.Contains("working directory", ex.Message);
    }

    [Theory]
    [InlineData("lib", "relative")]
    [InlineData("./lib", "relative")]
    [InlineData("$ORIGIN/lib", "dynamic string token")]
    [InlineData("/usr/${LIB}", "dynamic string token")]
    public void ALibraryPathThatCantBeCheckedInAdvance_IsRefused(string value, string reason)
    {
        var ex = Assert.Throws<SecurityException>(() => VerifyEnvironment(StandardHost(), "LD_LIBRARY_PATH", value));

        Assert.Contains(reason, ex.Message);
    }

    [Fact]
    public void EveryValueTheVariableHasHad_IsChecked()
    {
        // A clean current value must not hide what the process started with.
        Assert.Throws<SecurityException>(() => VerifyEnvironment(StandardHost(), "LD_LIBRARY_PATH", "/usr/lib", "/home/dev/lib"));
    }

    [Theory]
    [InlineData("LD_PRELOAD", "libjemalloc.so.2")]                        // a bare name: found by the checked search
    [InlineData("LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libc.so.6")]
    [InlineData("LD_PRELOAD", "libjemalloc.so.2 /lib/x86_64-linux-gnu/libc.so.6")]
    [InlineData("LD_PRELOAD", "   ")]
    [InlineData("LD_AUDIT", "/usr/lib/x86_64-linux-gnu/libc.so.6:libaudit.so")]
    public void PreloadingOrAuditingFromRootControlledLocations_Passes(string variable, string value)
        => VerifyEnvironment(StandardHost(), variable, value);

    [Theory]
    [InlineData("LD_PRELOAD", "/home/dev/lib/libtss2-esys.so.0")]
    [InlineData("LD_PRELOAD", "libjemalloc.so.2 /home/dev/lib/libtss2-esys.so.0")]
    [InlineData("LD_PRELOAD", "libjemalloc.so.2:/home/dev/lib/libtss2-esys.so.0")]
    [InlineData("LD_PRELOAD", "./evil.so")]
    [InlineData("LD_PRELOAD", "$LIB/evil.so")]
    [InlineData("LD_AUDIT", "/home/dev/lib/libtss2-esys.so.0")]
    [InlineData("LD_AUDIT", "lib/evil.so")]
    public void PreloadingOrAuditingFromAnywhereElse_IsRefused(string variable, string value)
    {
        var ex = Assert.Throws<SecurityException>(() => VerifyEnvironment(StandardHost(), variable, value));

        Assert.Contains(variable, ex.Message);
    }

    [Fact]
    public void ALocationThatCannotBeExamined_IsRefused()
    {
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyEnvironment(
            new Dictionary<string, IReadOnlyList<string>> { ["LD_LIBRARY_PATH"] = ["/srv/lib"] },
            (_, _) => throw new IOException("statx('/srv') failed with errno 13.")));

        Assert.Contains("errno 13", ex.Message);
        Assert.IsType<IOException>(ex.InnerException);
    }

    // --- What was loaded ------------------------------------------------------------------------

    [Fact]
    public void VerifyLoadedImage_Accepts_TheVerifiedPath()
        => LinuxNativeLibraryLoader.VerifyLoadedImage(Library, Library);

    [Fact]
    public void VerifyLoadedImage_Refuses_AnotherFile()
    {
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyLoadedImage(Library, "/usr/lib64/libhkdfguard.so.1"));

        Assert.Contains("/usr/lib64/libhkdfguard.so.1", ex.Message);
    }

    [Fact]
    public void VerifyLoadedImage_Refuses_WhenTheLoadedFileHasNoProbeExport()
    {
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyLoadedImage(Library, null));

        Assert.Contains(LinuxNativeLibraryLoader.ProbeExport, ex.Message);
    }

    [Fact]
    public void TheProbeExport_IsOneTheBindingCalls()
        => Assert.Equal("hkdfguard_wrap_dek", LinuxNativeLibraryLoader.ProbeExport);

    // The installed library's closure, as ldd reports it on Ubuntu 24.04.
    private static readonly Dictionary<string, string[]> Needed = new()
    {
        [Library] = ["libtss2-esys.so.0", "libgcc_s.so.1", "libc.so.6"],
        [Esys] = ["libtss2-mu.so.0", "libcrypto.so.3", "libc.so.6"],
        [$"{LibDir}/libtss2-mu.so.0.0.1"] = ["libc.so.6"],
        [$"{LibDir}/libcrypto.so.3"] = ["libc.so.6"],
        [$"{LibDir}/libgcc_s.so.1"] = ["libc.so.6"],
        [$"{LibDir}/libc.so.6"] = ["ld-linux-x86-64.so.2"],
        [$"{LibDir}/ld-linux-x86-64.so.2"] = [],
    };

    private static readonly Dictionary<string, string> Loaded = new()
    {
        ["libtss2-esys.so.0"] = "/lib/x86_64-linux-gnu/libtss2-esys.so.0",
        ["libtss2-mu.so.0"] = "/lib/x86_64-linux-gnu/libtss2-mu.so.0",
        ["libcrypto.so.3"] = "/lib/x86_64-linux-gnu/libcrypto.so.3",
        ["libgcc_s.so.1"] = "/lib/x86_64-linux-gnu/libgcc_s.so.1",
        ["libc.so.6"] = "/lib/x86_64-linux-gnu/libc.so.6",
        ["ld-linux-x86-64.so.2"] = "/lib64/ld-linux-x86-64.so.2",
    };

    private static FileSystem HostWithClosure() => StandardHost()
        .Link($"{LibDir}/libtss2-mu.so.0", "libtss2-mu.so.0.0.1").File($"{LibDir}/libtss2-mu.so.0.0.1")
        .File($"{LibDir}/libcrypto.so.3").File($"{LibDir}/libgcc_s.so.1")
        .Link("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2").File($"{LibDir}/ld-linux-x86-64.so.2");

    private static void VerifyDependencies(FileSystem fs, Dictionary<string, string> loaded, List<string>? read = null)
        => LinuxNativeLibraryLoader.VerifyDependencies(
            Library,
            file =>
            {
                read?.Add(file);
                return Needed[file];
            },
            loaded.GetValueOrDefault,
            p => fs.Resolve(p)!);

    [Fact]
    public void ATrustedDependencyClosure_Passes_AndEveryFileInItIsRead_Once()
    {
        var read = new List<string>();
        VerifyDependencies(HostWithClosure(), Loaded, read);

        Assert.Equal(Needed.Keys.Order(), read.Order());
    }

    [Fact]
    public void ADirectDependency_LoadedFromAUsersDirectory_IsRefused()
    {
        var loaded = new Dictionary<string, string>(Loaded) { ["libtss2-esys.so.0"] = "/home/dev/lib/libtss2-esys.so.0" };

        var ex = Assert.Throws<SecurityException>(() => VerifyDependencies(HostWithClosure(), loaded));
        Assert.Contains("'libtss2-esys.so.0'", ex.Message);
        Assert.Contains(Library, ex.Message);
    }

    [Fact]
    public void ATransitiveDependency_LoadedFromAnUntrustedDirectory_IsRefused()
    {
        var fs = HostWithClosure().File("/tmp/libcrypto.so.3");
        var loaded = new Dictionary<string, string>(Loaded) { ["libcrypto.so.3"] = "/tmp/libcrypto.so.3" };

        var ex = Assert.Throws<SecurityException>(() => VerifyDependencies(fs, loaded));
        Assert.Contains("'libcrypto.so.3' (needed by '" + Esys + "')", ex.Message);
    }

    [Fact]
    public void ADependencyNothingAnswersTo_IsRefused()
    {
        var loaded = new Dictionary<string, string>(Loaded);
        loaded.Remove("libgcc_s.so.1");

        var ex = Assert.Throws<SecurityException>(() => VerifyDependencies(HostWithClosure(), loaded));
        Assert.Contains("libgcc_s.so.1", ex.Message);
    }

    [Fact]
    public void ADependencyThatCannotBeExamined_IsRefused()
    {
        var ex = Assert.Throws<SecurityException>(() => LinuxNativeLibraryLoader.VerifyDependencies(
            Library, _ => ["libc.so.6"], _ => "/lib/x86_64-linux-gnu/libc.so.6", _ => throw new IOException("statx failed with errno 13.")));

        Assert.IsType<IOException>(ex.InnerException);
    }
}

/// <summary>DT_NEEDED parsing, against synthetic ELF images and, where installed, the real library.</summary>
public class ElfDependenciesTests
{
    private const ulong LoadAddress = 0x40_0000;

    /// <summary>
    /// A minimal 64-bit little-endian ELF image: one PT_LOAD mapping the whole file at
    /// <see cref="LoadAddress"/>, one PT_DYNAMIC, and a string table holding the given names.
    /// </summary>
    private static byte[] Elf(string[] needed, bool withDynamic = true, bool withStringTable = true, ulong? stringTableAddressOverride = null, ulong? neededOffsetOverride = null, int stringTableSizeAdjustment = 0, bool withStringTableSize = true)
    {
        const int header = 64, phdrs = 2 * 56;
        var strings = new List<byte> { 0 };
        var offsets = new List<ulong>();
        foreach (var name in needed)
        {
            offsets.Add(neededOffsetOverride ?? (ulong)strings.Count);
            strings.AddRange(Encoding.UTF8.GetBytes(name));
            strings.Add(0);
        }

        var dynamicEntries = new List<(long Tag, ulong Value)>();
        dynamicEntries.AddRange(offsets.Select(o => (1L, o)));
        var stringTableOffset = header + phdrs + (needed.Length + 3) * 16;
        if (withStringTable)
        {
            dynamicEntries.Add((5, stringTableAddressOverride ?? LoadAddress + (ulong)stringTableOffset));
            if (withStringTableSize)
                dynamicEntries.Add((10, (ulong)(strings.Count + stringTableSizeAdjustment)));
        }
        dynamicEntries.Add((0, 0));

        var image = new byte[stringTableOffset + strings.Count];
        image[0] = 0x7F; image[1] = (byte)'E'; image[2] = (byte)'L'; image[3] = (byte)'F';
        image[4] = 2; image[5] = 1; image[6] = 1;
        BitConverter.TryWriteBytes(image.AsSpan(32), (ulong)header);   // e_phoff
        BitConverter.TryWriteBytes(image.AsSpan(54), (ushort)56);      // e_phentsize
        BitConverter.TryWriteBytes(image.AsSpan(56), (ushort)2);       // e_phnum

        void ProgramHeader(int index, uint type, ulong offset, ulong address, ulong size)
        {
            var at = header + index * 56;
            BitConverter.TryWriteBytes(image.AsSpan(at), type);
            BitConverter.TryWriteBytes(image.AsSpan(at + 8), offset);
            BitConverter.TryWriteBytes(image.AsSpan(at + 16), address);
            BitConverter.TryWriteBytes(image.AsSpan(at + 32), size);
        }

        var dynamicOffset = header + phdrs;
        ProgramHeader(0, 1, 0, LoadAddress, (ulong)image.Length);
        ProgramHeader(1, withDynamic ? 2u : 4u, (ulong)dynamicOffset, LoadAddress + (ulong)dynamicOffset, (ulong)(dynamicEntries.Count * 16));
        for (var i = 0; i < dynamicEntries.Count; i++)
        {
            BitConverter.TryWriteBytes(image.AsSpan(dynamicOffset + i * 16), dynamicEntries[i].Tag);
            BitConverter.TryWriteBytes(image.AsSpan(dynamicOffset + i * 16 + 8), dynamicEntries[i].Value);
        }

        strings.ToArray().CopyTo(image, stringTableOffset);
        return image;
    }

    private static IReadOnlyList<string> Parse(byte[] image)
        => ElfDependencies.ReadNeeded("test.so", (offset, count) => offset + count <= image.Length ? image.AsSpan((int)offset, count).ToArray() : null);

    [Fact]
    public void ReadsEveryNeededName_InOrder()
        => Assert.Equal(["libtss2-esys.so.0", "libc.so.6"], Parse(Elf(["libtss2-esys.so.0", "libc.so.6"])));

    [Fact]
    public void AnObjectWithNoDependencies_HasNone()
    {
        Assert.Empty(Parse(Elf([])));
        Assert.Empty(Parse(Elf([], withStringTable: false)));
        Assert.Empty(Parse(Elf(["ignored.so"], withDynamic: false)));
    }

    public static TheoryData<string, byte[]> MalformedImages()
    {
        var notElf = Elf(["x.so"]);
        notElf[1] = (byte)'X';
        var elf32 = Elf(["x.so"]);
        elf32[4] = 1;
        var bigEndian = Elf(["x.so"]);
        bigEndian[5] = 2;
        var noProgramHeaders = Elf(["x.so"]);
        BitConverter.TryWriteBytes(noProgramHeaders.AsSpan(56), (ushort)0);
        var hugeOffset = Elf(["x.so"]);
        BitConverter.TryWriteBytes(hugeOffset.AsSpan(32), ulong.MaxValue);
        var hugeDynamic = Elf(["x.so"]);
        BitConverter.TryWriteBytes(hugeDynamic.AsSpan(64 + 56 + 32), (ulong)(2 << 20));

        return new TheoryData<string, byte[]>
        {
            { "not an ELF file", notElf },
            { "not a 64-bit little-endian", elf32 },
            { "not a 64-bit little-endian", bigEndian },
            { "program header table is malformed", noProgramHeaders },
            { "out of range", hugeOffset },
            { "implausibly large", hugeDynamic },
            { "runs past the end", Elf(["x.so"])[..40] },
            { "runs past the end", Elf(["x.so"])[..^3] },
            { "no string table", Elf(["x.so"], withStringTable: false) },
            { "no string table", Elf(["x.so"], withStringTableSize: false) }, // DT_STRTAB without DT_STRSZ
            { "outside every loaded segment", Elf(["x.so"], stringTableAddressOverride: 0x10) },
            { "runs past its string table", Elf(["x.so"], neededOffsetOverride: 4096) },
            { "runs past its string table", Elf(["x.so"], stringTableSizeAdjustment: -1) }, // no terminating NUL
        };
    }

    [Theory]
    [MemberData(nameof(MalformedImages))]
    public void AMalformedImage_IsRefused(string reason, byte[] image)
    {
        var ex = Assert.Throws<SecurityException>(() => Parse(image));

        Assert.Contains("test.so", ex.Message);
        Assert.Contains(reason, ex.Message);
    }

    [Fact]
    public void ReadsFromAFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Elf(["libc.so.6"]));
            Assert.Equal(["libc.so.6"], ElfDependencies.ReadNeeded(path));

            File.WriteAllBytes(path, Elf(["libc.so.6"])[..100]);
            Assert.Throws<SecurityException>(() => ElfDependencies.ReadNeeded(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [InstalledLinuxLibraryFact]
    public void TheInstalledLibrary_NeedsTpm2TssAndLibc()
    {
        var needed = ElfDependencies.ReadNeeded(InstalledLinuxLibraryFactAttribute.InstalledPath!);

        Assert.Contains("libtss2-esys.so.0", needed);
        Assert.Contains("libc.so.6", needed);
    }
}
