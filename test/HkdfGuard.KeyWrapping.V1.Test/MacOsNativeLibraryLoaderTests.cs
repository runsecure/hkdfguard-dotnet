using System.Runtime.InteropServices;
using System.Security;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// The macOS loader's decisions - which install to use and whether its path and signature can be
/// trusted - checked against simulated filesystems, so they run on every platform. The thin macOS
/// system-call layer (MacOsNative) only runs on a Mac.
/// </summary>
public class MacOsNativeLibraryLoaderTests
{
    private const uint Root = 0;
    private const uint User = 501;
    private const uint OtherUser = 502;
    private const uint Wheel = 0;
    private const uint Admin = 80;
    private const uint Staff = 20;
    private const string Home = "/Users/dev";

    private const UnixFileMode Mode755 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                         | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                         | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    private const UnixFileMode Mode775 = Mode755 | UnixFileMode.GroupWrite;
    private const UnixFileMode Mode644 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
    private const UnixFileMode Mode700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    private static readonly uint[] SystemOwners = [Root];
    private static readonly uint[] UserOwners = [Root, User];

    private static UnixFileStatus Dir(uint owner, uint group, UnixFileMode mode) => new(owner, group, mode, UnixFileType.Directory);
    private static UnixFileStatus File(uint owner, uint group, UnixFileMode mode) => new(owner, group, mode, UnixFileType.RegularFile);

    // A standard system install: /Library/Application Support is root:admin and group-writable.
    private static Dictionary<string, UnixFileStatus> SystemInstall() => new()
    {
        ["/"] = Dir(Root, Wheel, Mode755),
        ["/Library"] = Dir(Root, Wheel, Mode755),
        ["/Library/Application Support"] = Dir(Root, Admin, Mode775),
        ["/Library/Application Support/HkdfGuard"] = Dir(Root, Wheel, Mode755),
        ["/Library/Application Support/HkdfGuard/v1"] = Dir(Root, Wheel, Mode755),
        [MacOsNativeLibraryLoader.SystemPath] = File(Root, Wheel, Mode644),
    };

    // A standard per-user install under a user-owned home.
    private static Dictionary<string, UnixFileStatus> UserInstall() => new()
    {
        ["/"] = Dir(Root, Wheel, Mode755),
        ["/Users"] = Dir(Root, Admin, Mode755),
        [Home] = Dir(User, Staff, Mode755),
        [$"{Home}/.hkdfguard"] = Dir(User, Staff, Mode700),
        [$"{Home}/.hkdfguard/v1"] = Dir(User, Staff, Mode700),
        [MacOsNativeLibraryLoader.UserPath(Home)] = File(User, Staff, Mode644),
    };

    private static void Verify(Dictionary<string, UnixFileStatus> filesystem, string path, uint[] owners)
        => MacOsNativeLibraryLoader.VerifyLocation(path, p => filesystem[p], owners);

    // --- Platform -------------------------------------------------------------------------------

    [Theory]
    [InlineData(13, 0)]
    [InlineData(15, 4)]
    [InlineData(26, 0)]
    public void RequireSupportedPlatform_AcceptsArm64_OnMacOs13OrLater(int major, int minor)
    {
        MacOsNativeLibraryLoader.RequireSupportedPlatform(Architecture.Arm64, new Version(major, minor));
    }

    [Fact]
    public void RequireSupportedPlatform_RefusesX64_NamingRosetta()
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(() =>
            MacOsNativeLibraryLoader.RequireSupportedPlatform(Architecture.X64, new Version(15, 0)));

        Assert.Contains("Apple silicon", ex.Message);
        Assert.Contains("Rosetta", ex.Message);
    }

    [Theory]
    [InlineData(Architecture.X86)]
    [InlineData(Architecture.Arm)]
    public void RequireSupportedPlatform_RefusesEveryOtherArchitecture(Architecture architecture)
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(() =>
            MacOsNativeLibraryLoader.RequireSupportedPlatform(architecture, new Version(15, 0)));

        Assert.Contains(architecture.ToString(), ex.Message);
    }

    [Fact]
    public void RequireSupportedPlatform_RefusesMacOsOlderThan13()
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(() =>
            MacOsNativeLibraryLoader.RequireSupportedPlatform(Architecture.Arm64, new Version(12, 7, 6)));

        Assert.Contains("macOS 13", ex.Message);
        Assert.Contains("12.7.6", ex.Message);
    }

    // --- Locations ------------------------------------------------------------------------------

    [Fact]
    public void TheTwoLocations_AreTheAgreedPaths()
    {
        Assert.Equal("/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.SystemPath);
        Assert.Equal("/Users/dev/.hkdfguard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.UserPath("/Users/dev"));
        Assert.Equal("/Users/dev/.hkdfguard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.UserPath("/Users/dev/"));
    }

    // lstat results for ChoosePath's probe.
    private const int Present = 0;
    private const int ENOENT = 2;
    private const int EACCES = 13;
    private const int ENOTDIR = 20;

    [Fact]
    public void ChoosePath_PrefersTheSystemInstall_EvenWhenAUserInstallExists()
    {
        var (path, isSystem) = MacOsNativeLibraryLoader.ChoosePath(_ => Present, Home);

        Assert.Equal(MacOsNativeLibraryLoader.SystemPath, path);
        Assert.True(isSystem);
    }

    [Theory]
    [InlineData(ENOENT)]
    [InlineData(ENOTDIR)] // a parent of the system path is a file: still just "not there"
    public void ChoosePath_UsesTheUserInstall_OnlyWhenThereIsNoSystemInstall(int systemErrno)
    {
        var user = MacOsNativeLibraryLoader.UserPath(Home);

        var (path, isSystem) = MacOsNativeLibraryLoader.ChoosePath(p => p == user ? Present : systemErrno, Home);

        Assert.Equal(user, path);
        Assert.False(isSystem);
    }

    [Theory]
    [InlineData(EACCES)] // e.g. root installed HkdfGuard/ as 0700: the install exists but can't be seen
    [InlineData(62)]     // ELOOP
    [InlineData(5)]      // EIO
    public void ChoosePath_WhenTheSystemInstallCannotBeExamined_RefusesInsteadOfFallingBack(int errno)
    {
        var probed = new List<string>();

        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.ChoosePath(p => { probed.Add(p); return errno; }, Home));

        Assert.Contains(MacOsNativeLibraryLoader.SystemPath, ex.Message);
        Assert.Contains($"errno {errno}", ex.Message);
        Assert.Equal([MacOsNativeLibraryLoader.SystemPath], probed); // the user install was never even considered
    }

    [Fact]
    public void ChoosePath_WhenTheUserInstallCannotBeExamined_Refuses()
    {
        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.ChoosePath(p => p == MacOsNativeLibraryLoader.SystemPath ? ENOENT : EACCES, Home));

        Assert.Contains(MacOsNativeLibraryLoader.UserPath(Home), ex.Message);
    }

    [Fact]
    public void ChoosePath_WithNeitherInstallUsable_ThrowsNamingBothLocations()
    {
        var ex = Assert.Throws<DllNotFoundException>(() =>
            MacOsNativeLibraryLoader.ChoosePath(_ => ENOENT, Home));

        Assert.Contains(MacOsNativeLibraryLoader.SystemPath, ex.Message);
        Assert.Contains(MacOsNativeLibraryLoader.UserPath(Home), ex.Message);
    }

    [Theory]
    [InlineData(null)]             // no account database entry, or it couldn't be read
    [InlineData("")]               // an entry with no home directory
    [InlineData("relative/home")]  // never resolved against the working directory
    public void ChoosePath_WithNoUsableAccountHome_ConsidersOnlyTheSystemInstall(string? home)
    {
        var probed = new List<string>();

        var ex = Assert.Throws<DllNotFoundException>(() =>
            MacOsNativeLibraryLoader.ChoosePath(p => { probed.Add(p); return p.EndsWith(".dylib") && !p.StartsWith('/') ? Present : ENOENT; }, home));

        Assert.Equal([MacOsNativeLibraryLoader.SystemPath], probed);
        Assert.Contains(MacOsNativeLibraryLoader.SystemPath, ex.Message);
        Assert.DoesNotContain(".hkdfguard", ex.Message);
    }

    [Fact]
    public void ChoosePath_WithNoUsableAccountHome_StillUsesTheSystemInstall()
    {
        var (path, isSystem) = MacOsNativeLibraryLoader.ChoosePath(_ => Present, null);

        Assert.Equal(MacOsNativeLibraryLoader.SystemPath, path);
        Assert.True(isSystem);
    }

    // --- The library's version ------------------------------------------------------------------

    private const uint Arm64 = 0x0100000C;
    private const uint X86_64 = 0x01000007;

    // A thin Mach-O 64 header followed by the given load commands, each as (cmd, cmdsize, body).
    private static byte[] MachO(uint cpuType, params (uint Cmd, uint Size, uint? Version)[] commands)
    {
        var body = new List<byte>();
        foreach (var (cmd, size, version) in commands)
        {
            var command = new byte[size];
            BitConverter.GetBytes(cmd).CopyTo(command, 0);
            BitConverter.GetBytes(size).CopyTo(command, 4);
            if (version is { } v && size >= 24)
                BitConverter.GetBytes(v).CopyTo(command, 16);
            body.AddRange(command);
        }
        var header = new byte[32];
        BitConverter.GetBytes(0xFEEDFACFu).CopyTo(header, 0);
        BitConverter.GetBytes(cpuType).CopyTo(header, 4);
        BitConverter.GetBytes((uint)commands.Length).CopyTo(header, 16);
        BitConverter.GetBytes((uint)body.Count).CopyTo(header, 20);
        return [.. header, .. body];
    }

    private static byte[] Dylib(uint version, uint cpuType = Arm64) =>
        MachO(cpuType, (0x19, 72, null), (0xD, 48, version), (0x32, 32, null)); // LC_SEGMENT_64, LC_ID_DYLIB, LC_BUILD_VERSION

    private static void PutBigEndian(byte[] buffer, int at, uint value)
    {
        buffer[at] = (byte)(value >> 24); buffer[at + 1] = (byte)(value >> 16); buffer[at + 2] = (byte)(value >> 8); buffer[at + 3] = (byte)value;
    }

    // A universal file: a FAT_MAGIC header with one 20-byte entry per slice, slices at 4 KiB boundaries.
    private static byte[] Fat(params (uint CpuType, byte[] Slice)[] slices)
    {
        const int align = 4096;
        var file = new byte[align * (slices.Length + 1)];
        PutBigEndian(file, 0, 0xCAFEBABE);
        PutBigEndian(file, 4, (uint)slices.Length);
        for (var i = 0; i < slices.Length; i++)
        {
            var offset = align * (i + 1);
            PutBigEndian(file, 8 + i * 20, slices[i].CpuType);
            PutBigEndian(file, 8 + i * 20 + 8, (uint)offset);
            PutBigEndian(file, 8 + i * 20 + 12, (uint)slices[i].Slice.Length);
            slices[i].Slice.CopyTo(file, offset);
        }
        return file;
    }

    [Theory]
    [InlineData(0x0000_0900u)] // the minimum itself, 0.9.0
    [InlineData(0x0000_0901u)] // 0.9.1
    [InlineData(0x0001_0000u)] // 1.0.0
    public void VerifyVersion_AcceptsTheMinimumAndNewer(uint version)
    {
        Assert.Equal(version, MacOsNativeLibraryLoader.ReadLibraryVersion(Dylib(version)));
        MacOsNativeLibraryLoader.VerifyVersion("/x.dylib", Dylib(version));
    }

    [Theory]
    [InlineData(0x0000_0800u, "0.8.0")]
    [InlineData(0x0000_08FFu, "0.8.255")]
    [InlineData(0x0000_0000u, "0.0.0")]
    public void VerifyVersion_RefusesAnOlderRelease_NamingBothVersions(uint version, string shown)
    {
        var ex = Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifyVersion("/x.dylib", Dylib(version)));

        Assert.Contains($"version {shown}", ex.Message);
        Assert.Contains("(0.9.0)", ex.Message);
    }

    public static TheoryData<string, byte[]> UnreadableLibraries() => new()
    {
        { "empty", [] },
        { "truncated header", Dylib(0x0000_0900)[..20] },
        { "wrong magic", [.. new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' }, .. Dylib(0x0000_0900)[4..]] },
        { "x86_64 only", Dylib(0x0000_0900, X86_64) },
        { "no LC_ID_DYLIB", MachO(Arm64, (0x19, 72, null), (0x32, 32, null)) },
        { "LC_ID_DYLIB too short", MachO(Arm64, (0xD, 16, null)) },
        { "cmdsize zero", MachO(Arm64, (0x19, 8, null)) is var z ? Patch(z, 36, 0) : [] },
        { "cmdsize not a multiple of 8", Patch(Dylib(0x0000_0900), 36, 70) },
        { "cmdsize past the commands", Patch(Dylib(0x0000_0900), 36, 0x7FFF_FFF8) },
        { "sizeofcmds past the data", Patch(Dylib(0x0000_0900), 20, 0x7FFF_FFF8) },
        { "ncmds larger than sizeofcmds allows", Patch(Dylib(0x0000_0900), 16, 1000) },
        { "fat without an arm64 slice", Fat((X86_64, Dylib(0x0000_0900, X86_64))) },
        { "fat with an arm64 slice outside the data", Patch(Fat((Arm64, Dylib(0x0000_0900))), 16, 0x0100_0000, bigEndian: true) },
        { "fat claiming more slices than fit", Patch(Fat((Arm64, Dylib(0x0000_0900))), 4, 1000, bigEndian: true) },
    };

    private static byte[] Patch(byte[] data, int at, uint value, bool bigEndian = false)
    {
        var copy = (byte[])data.Clone();
        if (bigEndian)
            PutBigEndian(copy, at, value);
        else
            BitConverter.GetBytes(value).CopyTo(copy, at);
        return copy;
    }

    [Theory]
    [MemberData(nameof(UnreadableLibraries))]
    public void VerifyVersion_RefusesAFileWhoseVersionCannotBeRead(string why, byte[] data)
    {
        Assert.Null(MacOsNativeLibraryLoader.ReadLibraryVersion(data));
        var ex = Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifyVersion("/x.dylib", data));
        Assert.Contains("version can be read", ex.Message);
        Assert.NotEmpty(why);
    }

    [Fact]
    public void ReadLibraryVersion_ReadsTheArm64SliceOfAUniversalFile()
    {
        var fat = Fat((X86_64, Dylib(0x0000_0800, X86_64)), (Arm64, Dylib(0x0000_0902)));

        Assert.Equal(0x0000_0902u, MacOsNativeLibraryLoader.ReadLibraryVersion(fat));
    }

    [Fact]
    public void GetAccountHomeDirectory_OnMacOs_IsAnExistingAbsoluteFolder_NotTakenFromHome()
    {
        if (!OperatingSystem.IsMacOS())
            return;

        var home = MacOsNative.GetAccountHomeDirectory();

        Assert.NotNull(home);
        Assert.StartsWith("/", home);
        Assert.True(Directory.Exists(home), home);
    }

    [Fact]
    public void TheInstalledLibrary_WhenPresent_PassesTheVersionCheck()
    {
        var path = MacOsNativeLibraryLoader.SystemPath;
        if (!System.IO.File.Exists(path))
            return; // not installed on this host

        var head = System.IO.File.ReadAllBytes(path).AsSpan(0, Math.Min((int)new FileInfo(path).Length, MacOsNativeLibraryLoader.VersionReadLimit)).ToArray();
        var version = MacOsNativeLibraryLoader.ReadLibraryVersion(head);

        Assert.NotNull(version);
        Assert.True(version >= MacOsNativeLibraryLoader.MinimumLibraryVersion, $"installed version {MacOsNativeLibraryLoader.FormatVersion(version!.Value)}");
        MacOsNativeLibraryLoader.VerifyVersion(path, head);
    }

    [Theory]
    [InlineData("/a/b/c.dylib", "/a/b")]
    [InlineData("/a/b/", "/a")]
    [InlineData("/a", "/")]
    [InlineData("/", null)]
    public void ParentOf_WalksSlashSeparatedPathsUpToRoot(string path, string? parent)
    {
        Assert.Equal(parent, MacOsNativeLibraryLoader.ParentOf(path));
    }

    // --- Path integrity ---------------------------------------------------------------------------

    [Fact]
    public void AStandardSystemInstall_Passes()
    {
        Verify(SystemInstall(), MacOsNativeLibraryLoader.SystemPath, SystemOwners);
    }

    [Fact]
    public void AStandardUserInstall_Passes()
    {
        Verify(UserInstall(), MacOsNativeLibraryLoader.UserPath(Home), UserOwners);
    }

    [Fact]
    public void ASystemInstall_OwnedByAUser_IsRefused()
    {
        var fs = SystemInstall();
        fs["/Library/Application Support/HkdfGuard/v1"] = Dir(User, Staff, Mode755);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));

        Assert.Contains("owned by uid 501", ex.Message);
        Assert.Contains("owned by root.", ex.Message);
    }

    [Fact]
    public void AUserInstall_OwnedByAnotherUser_IsRefused()
    {
        var fs = UserInstall();
        fs[MacOsNativeLibraryLoader.UserPath(Home)] = File(OtherUser, Staff, Mode644);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners));

        Assert.Contains("owned by uid 502", ex.Message);
        Assert.Contains("root or the current user", ex.Message);
    }

    [Fact]
    public void AnyWorldWritableComponent_IsRefused()
    {
        var fs = UserInstall();
        fs[$"{Home}/.hkdfguard"] = Dir(User, Staff, Mode700 | UnixFileMode.OtherWrite);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners));

        Assert.Contains("writable by every user", ex.Message);
    }

    [Fact]
    public void AGroupWritableComponent_OwnedByAUser_IsRefused()
    {
        var fs = UserInstall();
        fs[Home] = Dir(User, Staff, Mode775);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners));

        Assert.Contains("writable by group 20", ex.Message);
    }

    [Fact]
    public void AGroupWritableRootDirectory_IsRefused_UnlessTheGroupIsWheelOrAdmin()
    {
        var fs = SystemInstall();
        fs["/Library/Application Support"] = Dir(Root, Staff, Mode775);

        Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));

        fs["/Library/Application Support"] = Dir(Root, Wheel, Mode775);
        Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/Library")]
    [InlineData("/Library/Application Support")]
    public void TheSystemDirectoriesAboveASystemInstall_MayBeAdminWritable(string directory)
    {
        var fs = SystemInstall();
        fs[directory] = Dir(Root, Admin, Mode775);

        Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners);
    }

    [Fact]
    public void Users_MayBeAdminWritable_AboveAUserInstall()
    {
        var fs = UserInstall();
        fs["/Users"] = Dir(Root, Admin, Mode775);

        Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners);
    }

    [Theory]
    [InlineData("/Library/Application Support/HkdfGuard")]
    [InlineData("/Library/Application Support/HkdfGuard/v1")]
    public void TheInstallsOwnDirectories_AreNeverAdminWritable_EvenWhenRootOwned(string directory)
    {
        foreach (var group in new[] { Wheel, Admin })
        {
            var fs = SystemInstall();
            fs[directory] = Dir(Root, group, Mode775);

            var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));

            Assert.Contains($"'{directory}' is writable by group {group}", ex.Message);
        }
    }

    [Fact]
    public void TheLibraryFile_IsNeverAdminWritable_EvenWhenRootOwned()
    {
        var fs = SystemInstall();
        fs[MacOsNativeLibraryLoader.SystemPath] = File(Root, Admin, Mode644 | UnixFileMode.GroupWrite);

        Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));
    }

    [Fact]
    public void AnotherRootOwnedDirectory_IsNotAdminWritable_JustBecauseItLooksLikeASystemOne()
    {
        // The exception is by exact path: a root-owned, admin-writable directory elsewhere - here
        // a home directory a user install sits under - gets no exception.
        var fs = UserInstall();
        fs[Home] = Dir(Root, Admin, Mode775);

        Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners));
    }

    [Fact]
    public void ASymbolicLinkedDirectory_IsRefused()
    {
        var fs = UserInstall();
        fs[$"{Home}/.hkdfguard"] = new UnixFileStatus(User, Staff, Mode755, UnixFileType.SymbolicLink);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.UserPath(Home), UserOwners));

        Assert.Contains("is not a directory (it is a symbolic link)", ex.Message);
    }

    [Theory]
    [InlineData((int)UnixFileType.SymbolicLink, "symbolic link")]
    [InlineData((int)UnixFileType.Directory, "directory")]
    [InlineData((int)UnixFileType.Other, "special file")]
    public void TheLibraryItself_MustBeARegularFile(int fileType, string described)
    {
        var type = (UnixFileType)fileType;
        var fs = SystemInstall();
        fs[MacOsNativeLibraryLoader.SystemPath] = new UnixFileStatus(Root, Wheel, Mode644, type);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));

        Assert.Contains($"(it is a {described})", ex.Message);
    }

    [Fact]
    public void ADirectoryThatIsARegularFile_IsDescribedAsSuch()
    {
        var fs = SystemInstall();
        fs["/Library/Application Support/HkdfGuard"] = File(Root, Wheel, Mode755);

        var ex = Assert.Throws<SecurityException>(() => Verify(fs, MacOsNativeLibraryLoader.SystemPath, SystemOwners));

        Assert.Contains("(it is a regular file)", ex.Message);
    }

    // --- Code signature ---------------------------------------------------------------------------

    [Fact]
    public void TheCodeRequirement_PinsTheHkdfGuardTeam()
    {
        Assert.Equal("MFW3T8R8J3", MacOsNativeLibraryLoader.TeamId);
        Assert.Equal(
            "identifier \"libhkdfguard\" and anchor apple generic"
            + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"MFW3T8R8J3\"",
            MacOsNativeLibraryLoader.CodeRequirement);
    }

    [Fact]
    public void VerifySignature_PassesTheRequirement_AndAcceptsSuccess()
    {
        string? checkedRequirement = null;

        MacOsNativeLibraryLoader.VerifySignature("/x.dylib", (_, requirement) =>
        {
            checkedRequirement = requirement;
            return 0;
        });

        Assert.Equal(MacOsNativeLibraryLoader.CodeRequirement, checkedRequirement);
    }

    [Theory]
    [InlineData(-67050)] // errSecCSReqFailed: signed, but not by this team
    [InlineData(-67062)] // errSecCSUnsigned
    public void VerifySignature_RefusesAnyFailure(int osStatus)
    {
        var ex = Assert.Throws<SecurityException>(() => MacOsNativeLibraryLoader.VerifySignature("/x.dylib", (_, _) => osStatus));

        Assert.Contains("MFW3T8R8J3", ex.Message);
        Assert.Contains(osStatus.ToString(), ex.Message);
    }

    // --- What dyld loads ------------------------------------------------------------------------
    // dlopen("/abs/path/libX.dylib") first looks for libX.dylib in each DYLD_LIBRARY_PATH directory.

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/opt/lib:/usr/local/lib")] // set, but no libhkdfguard.dylib in either
    public void RefuseShadowing_AllowsLoading_WhenNothingOnDyldLibraryPathHasTheLibrarysName(string? searchPath)
    {
        MacOsNativeLibraryLoader.RefuseShadowing(n => n == "DYLD_LIBRARY_PATH" ? searchPath : null, _ => false);
    }

    [Theory]
    [InlineData("DYLD_INSERT_LIBRARIES")]
    [InlineData("DYLD_FRAMEWORK_PATH")]
    [InlineData("DYLD_VERSIONED_LIBRARY_PATH")]
    [InlineData("DYLD_VERSIONED_FRAMEWORK_PATH")]
    [InlineData("DYLD_IMAGE_SUFFIX")]
    public void RefuseShadowing_Refuses_WhenADyldVariableThatInjectsOrSubstitutesCodeIsSet(string variable)
    {
        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.RefuseShadowing(n => n == variable ? "/tmp/inject.dylib" : null, _ => false));

        Assert.Contains(variable, ex.Message);
        Assert.Equal(variable, Assert.Single(MacOsNativeLibraryLoader.RefusedDyldVariables, v => v == variable));
        // Set but empty is the same as unset.
        MacOsNativeLibraryLoader.RefuseShadowing(n => n == variable ? "" : null, _ => false);
    }

    [Theory]
    [InlineData("/tmp/decoy", "/tmp/decoy/libhkdfguard.dylib")]
    [InlineData("/opt/lib:/tmp/decoy/:/usr/local/lib", "/tmp/decoy/libhkdfguard.dylib")] // any entry; a trailing slash is fine
    public void RefuseShadowing_Refuses_WhenADyldLibraryPathDirectoryHoldsALibraryOfTheSameName(string searchPath, string decoy)
    {
        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.RefuseShadowing(n => n == "DYLD_LIBRARY_PATH" ? searchPath : null, p => p == decoy));

        Assert.Contains(decoy, ex.Message);
        Assert.Contains("DYLD_LIBRARY_PATH", ex.Message);
    }

    [Fact]
    public void RefuseShadowing_ConsultsOnlyTheDyldVariablesItChecks()
    {
        var asked = new List<string>();

        MacOsNativeLibraryLoader.RefuseShadowing(name => { asked.Add(name); return null; }, _ => true);

        Assert.Equal([.. MacOsNativeLibraryLoader.RefusedDyldVariables, "DYLD_LIBRARY_PATH"], asked);
    }

    [Fact]
    public void VerifyLoadedImage_Accepts_TheVerifiedPath()
    {
        MacOsNativeLibraryLoader.VerifyLoadedImage(MacOsNativeLibraryLoader.SystemPath, MacOsNativeLibraryLoader.SystemPath);
    }

    [Fact]
    public void VerifyLoadedImage_Refuses_WhenDyldLoadedAnotherFile()
    {
        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.VerifyLoadedImage(MacOsNativeLibraryLoader.SystemPath, "/tmp/decoy/libhkdfguard.dylib"));

        Assert.Contains("/tmp/decoy/libhkdfguard.dylib", ex.Message);
        Assert.Contains(MacOsNativeLibraryLoader.SystemPath, ex.Message);
        Assert.Contains("unloaded", ex.Message);
    }

    [Fact]
    public void VerifyLoadedImage_Refuses_WhenTheLoadedFileHasNoProbeExport()
    {
        var ex = Assert.Throws<SecurityException>(() =>
            MacOsNativeLibraryLoader.VerifyLoadedImage(MacOsNativeLibraryLoader.SystemPath, null));

        Assert.Contains(MacOsNativeLibraryLoader.ProbeExport, ex.Message);
    }

    [Fact]
    public void TheProbeExport_IsOneTheBindingCalls()
    {
        Assert.Equal("hkdfguard_wrap_dek", MacOsNativeLibraryLoader.ProbeExport);
    }

    [Theory]
    [InlineData("Windows", "HkdfGuard.Kms.Windows.v1", 1)] // Windows library on Windows: the Windows loader
    [InlineData("OSX", "hkdfguard_v1", 2)]      // macOS library on macOS: the macOS loader
    [InlineData("Linux", "HkdfGuard.Kms.Linux.v1", 3)] // Linux library on Linux: the Linux loader
    [InlineData("OSX", "HkdfGuard.Kms.Windows.v1", 0)] // a KMS library name on the wrong platform: default
    [InlineData("Windows", "hkdfguard_v1", 0)]
    [InlineData("Linux", "hkdfguard_v1", 0)]
    [InlineData("Linux", "HkdfGuard.Kms.Windows.v1", 0)]
    [InlineData("Windows", "HkdfGuard.Kms.Linux.v1", 0)]
    [InlineData("OSX", "HkdfGuard.Kms.Linux.v1", 0)]
    [InlineData("Windows", "wintrust.dll", 0)]  // any other import: default
    [InlineData("OSX", "libSystem.B.dylib", 0)]
    [InlineData("Linux", "libc.so.6", 0)]
    public void Resolver_SendsEachPlatformsLibraryToItsOwnLoader_AndEverythingElseToTheDefault(string platform, string libraryName, int expected)
    {
        var routed = NativeLibraryResolver.Route(libraryName, p => p == OSPlatform.Create(platform), () => 1, () => 2, () => 3);

        Assert.Equal(expected, (int)routed);
    }
}
