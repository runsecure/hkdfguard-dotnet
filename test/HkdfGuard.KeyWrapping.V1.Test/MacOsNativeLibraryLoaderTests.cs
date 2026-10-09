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

    // --- Locations ------------------------------------------------------------------------------

    [Fact]
    public void TheTwoLocations_AreTheAgreedPaths()
    {
        Assert.Equal("/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib", MacOsNativeLibraryLoader.SystemPath);
        Assert.Equal("/Users/dev/.hkdfguard/v1/libhkdfguard_v1.dylib", MacOsNativeLibraryLoader.UserPath("/Users/dev"));
        Assert.Equal("/Users/dev/.hkdfguard/v1/libhkdfguard_v1.dylib", MacOsNativeLibraryLoader.UserPath("/Users/dev/"));
    }

    [Fact]
    public void ChoosePath_PrefersTheSystemInstall_EvenWhenAUserInstallExists()
    {
        var (path, isSystem) = MacOsNativeLibraryLoader.ChoosePath(_ => true, Home);

        Assert.Equal(MacOsNativeLibraryLoader.SystemPath, path);
        Assert.True(isSystem);
    }

    [Fact]
    public void ChoosePath_UsesTheUserInstall_OnlyWhenThereIsNoSystemInstall()
    {
        var user = MacOsNativeLibraryLoader.UserPath(Home);

        var (path, isSystem) = MacOsNativeLibraryLoader.ChoosePath(p => p == user, Home);

        Assert.Equal(user, path);
        Assert.False(isSystem);
    }

    [Theory]
    [InlineData(Home)]
    [InlineData("")]               // no home directory known
    [InlineData("relative/home")]  // never resolved against the working directory
    public void ChoosePath_WithNeitherInstallUsable_ThrowsNamingBothLocations(string home)
    {
        var ex = Assert.Throws<DllNotFoundException>(() =>
            MacOsNativeLibraryLoader.ChoosePath(p => !p.StartsWith('/') && p.EndsWith(".dylib"), home));

        Assert.Contains(MacOsNativeLibraryLoader.SystemPath, ex.Message);
        Assert.Contains(".hkdfguard/v1/libhkdfguard_v1.dylib", ex.Message);
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
        Assert.Equal("BQ4343E7W2", MacOsNativeLibraryLoader.TeamId);
        Assert.Equal("anchor apple generic and certificate leaf[subject.OU] = \"BQ4343E7W2\"", MacOsNativeLibraryLoader.CodeRequirement);
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

        Assert.Contains("BQ4343E7W2", ex.Message);
        Assert.Contains(osStatus.ToString(), ex.Message);
    }

    [Theory]
    [InlineData("Windows", "HkdfGuardV1", 1)]   // Windows library on Windows: the Windows loader
    [InlineData("OSX", "hkdfguard_v1", 2)]      // macOS library on macOS: the macOS loader
    [InlineData("OSX", "HkdfGuardV1", 0)]       // a KMS library name on the wrong platform: default
    [InlineData("Windows", "hkdfguard_v1", 0)]
    [InlineData("Linux", "hkdfguard_v1", 0)]
    [InlineData("Windows", "wintrust.dll", 0)]  // any other import: default
    [InlineData("OSX", "libSystem.B.dylib", 0)]
    public void Resolver_SendsEachPlatformsLibraryToItsOwnLoader_AndEverythingElseToTheDefault(string platform, string libraryName, int expected)
    {
        var routed = NativeLibraryResolver.Route(libraryName, p => p == OSPlatform.Create(platform), () => 1, () => 2);

        Assert.Equal(expected, (int)routed);
    }
}
