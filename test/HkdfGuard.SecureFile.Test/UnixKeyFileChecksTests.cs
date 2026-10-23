using HkdfGuard.SecureFile;

namespace HkdfGuard.SecureFile.Test;

/// <summary>
/// The Linux and macOS key-file location rules, checked against simulated filesystems so they run
/// on every platform. TrustedKeyFileTests runs them against the real filesystem.
/// </summary>
public class UnixKeyFileChecksTests
{
    private const uint Root = 0;
    private const uint Deployer = 1001;
    private const uint App = 1002;
    private const uint DeployersGroup = 2001;

    private const UnixFileMode Mode755 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                                         | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                                         | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
    private const UnixFileMode Mode775 = Mode755 | UnixFileMode.GroupWrite;
    private const UnixFileMode Mode1777 = Mode775 | UnixFileMode.OtherWrite | UnixFileMode.StickyBit;
    private const UnixFileMode Mode640 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
    private const UnixFileMode Mode660 = Mode640 | UnixFileMode.GroupWrite;
    private const UnixFileMode Mode777 = Mode775 | UnixFileMode.OtherWrite;

    private const string KeyFile = "/etc/hkdfguard/keys/v1.key";

    private static readonly KeyFileTrust DeployerTrust = new() { UnixUserIds = [Deployer], UnixGroupIds = [DeployersGroup] };

    /// <summary>A simulated filesystem: what lstat sees, and what each symbolic link holds.</summary>
    private sealed class FileSystem
    {
        public Dictionary<string, UnixFileStatus> Entries { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Links { get; } = new(StringComparer.Ordinal);

        public FileSystem Dir(string path, uint owner = Root, UnixFileMode mode = Mode755, uint? group = null)
        {
            Entries[path] = new UnixFileStatus(owner, group ?? owner, mode, UnixFileType.Directory);
            return this;
        }

        public FileSystem File(string path, uint owner = Root, UnixFileMode mode = Mode640, uint? group = null)
        {
            Entries[path] = new UnixFileStatus(owner, group ?? owner, mode, UnixFileType.RegularFile);
            return this;
        }

        public FileSystem Link(string path, string target, uint owner = Root)
        {
            Entries[path] = new UnixFileStatus(owner, owner, Mode777, UnixFileType.SymbolicLink);
            Links[path] = target;
            return this;
        }

        public FileSystem Other(string path)
        {
            Entries[path] = new UnixFileStatus(Root, Root, Mode640, UnixFileType.Other);
            return this;
        }

        public UnixFileStatus? Status(string path) => Entries.TryGetValue(path, out var status) ? status : null;

        public string? ReadLink(string path) => Links.GetValueOrDefault(path);

        public string Resolve(string path, KeyFileTrust? trust = null)
            => UnixKeyFileChecks.ResolveTrusted(path, trust ?? KeyFileTrust.AdministratorsOnly, Status, ReadLink);
    }

    private static FileSystem Standard() => new FileSystem()
        .Dir("/").Dir("/etc").Dir("/etc/hkdfguard").Dir("/etc/hkdfguard/keys", mode: Mode755);

    [Fact]
    public void RootOwnedThroughout_Resolves()
    {
        var fs = Standard().File(KeyFile);

        Assert.Equal(KeyFile, fs.Resolve(KeyFile));
    }

    [Fact]
    public void ReadableByOthers_IsNeverRefused()
    {
        var fs = Standard().File(KeyFile, mode: Mode640 | UnixFileMode.OtherRead);

        Assert.Equal(KeyFile, fs.Resolve(KeyFile));
    }

    [Fact]
    public void FileOwnedByTheApplication_IsRefused()
    {
        var fs = Standard().File(KeyFile, owner: App);

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
        Assert.Contains("uid 1002", ex.Message);
    }

    [Fact]
    public void FileOwnedByATrustedDeployer_Resolves()
    {
        var fs = Standard().File(KeyFile, owner: Deployer);

        Assert.Equal(KeyFile, fs.Resolve(KeyFile, DeployerTrust));
    }

    [Fact]
    public void DirectoryOwnedByAnUntrustedUser_IsRefused()
    {
        var fs = Standard().Dir("/etc/hkdfguard/keys", owner: App).File(KeyFile);

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
        Assert.Contains("'/etc/hkdfguard/keys'", ex.Message);
    }

    [Fact]
    public void UntrustedRoot_IsRefused()
    {
        var fs = Standard().Dir("/", mode: Mode777).File(KeyFile);

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
    }

    [Fact]
    public void RootThatCanNotBeExamined_IsRefused()
    {
        var fs = new FileSystem();

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
    }

    [Fact]
    public void WorldWritableDirectory_IsRefused_EvenWithTheStickyBit()
    {
        var fs = new FileSystem().Dir("/").Dir("/tmp", mode: Mode1777).Dir("/tmp/keys").File("/tmp/keys/v1.key");

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve("/tmp/keys/v1.key"));
        Assert.Contains("writable by every user", ex.Message);
    }

    [Fact]
    public void WorldWritableFile_IsRefused_WhateverIsTrusted()
    {
        var fs = Standard().File(KeyFile, mode: Mode777);

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile, DeployerTrust));
    }

    [Fact]
    public void GroupWritable_IsRefused_UnlessTheGroupIsTrusted()
    {
        var fs = Standard().Dir("/etc/hkdfguard/keys", mode: Mode775, group: DeployersGroup).File(KeyFile, mode: Mode660, group: DeployersGroup);

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
        Assert.Contains("group 2001", ex.Message);
        Assert.Equal(KeyFile, fs.Resolve(KeyFile, DeployerTrust));
    }

    [Fact]
    public void GroupWritableByAnotherGroup_IsRefused_EvenWithATrustedGroup()
    {
        var fs = Standard().File(KeyFile, mode: Mode660, group: App);

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile, DeployerTrust));
    }

    [Fact]
    public void RootOwnedSymbolicLink_IsFollowed_AndItsTargetChecked()
    {
        // macOS: /etc is a root-owned link to private/etc.
        var fs = new FileSystem().Dir("/").Link("/etc", "private/etc").Dir("/private").Dir("/private/etc")
            .Dir("/private/etc/hkdfguard").File("/private/etc/hkdfguard/v1.key");

        Assert.Equal("/private/etc/hkdfguard/v1.key", fs.Resolve("/etc/hkdfguard/v1.key"));
    }

    [Fact]
    public void AbsoluteSymbolicLink_RestartsFromRoot()
    {
        var fs = Standard().File(KeyFile).Dir("/srv").Link("/srv/current.key", KeyFile);

        Assert.Equal(KeyFile, fs.Resolve("/srv/current.key"));
    }

    [Fact]
    public void SymbolicLinkOwnedByAnUntrustedUser_IsNotFollowed()
    {
        var fs = Standard().File(KeyFile).Dir("/srv").Link("/srv/current.key", KeyFile, owner: App);

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve("/srv/current.key"));
        Assert.Contains("symbolic link owned by uid 1002", ex.Message);
    }

    [Fact]
    public void SymbolicLinkOwnedByATrustedDeployer_IsFollowed()
    {
        var fs = Standard().File(KeyFile).Dir("/srv").Link("/srv/current.key", KeyFile, owner: Deployer);

        Assert.Equal(KeyFile, fs.Resolve("/srv/current.key", DeployerTrust));
    }

    [Fact]
    public void SymbolicLinkIntoAnUntrustedDirectory_IsRefused()
    {
        var fs = Standard().Dir("/home").Dir("/home/app", owner: App).File("/home/app/v1.key", owner: App)
            .Link("/etc/hkdfguard/keys/v1.key", "/home/app/v1.key");

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
    }

    [Fact]
    public void SymbolicLinkLoop_IsRefused()
    {
        var fs = new FileSystem().Dir("/").Link("/a", "/b").Link("/b", "/a");

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve("/a"));
        Assert.Contains($"more than {UnixKeyFileChecks.MaxSymbolicLinks} symbolic links", ex.Message);
    }

    [Fact]
    public void UnreadableSymbolicLink_IsRefused()
    {
        var fs = Standard().File(KeyFile).Dir("/srv").Link("/srv/current.key", KeyFile);
        fs.Links.Remove("/srv/current.key");

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve("/srv/current.key"));
    }

    [Fact]
    public void DotAndDotDot_AreResolvedAfterLinks_TheWayTheKernelDoes()
    {
        var fs = Standard().File(KeyFile);

        Assert.Equal(KeyFile, fs.Resolve("/etc/./hkdfguard/keys/../keys//v1.key"));
        Assert.Equal(KeyFile, fs.Resolve("/../etc/hkdfguard/keys/v1.key"));
    }

    [Fact]
    public void MissingFile_IsNotFound()
    {
        var fs = Standard();

        Assert.Throws<FileNotFoundException>(() => fs.Resolve(KeyFile));
    }

    [Fact]
    public void PathThroughAFile_IsNotFound()
    {
        var fs = Standard().File(KeyFile);

        Assert.Throws<FileNotFoundException>(() => fs.Resolve($"{KeyFile}/more"));
    }

    [Fact]
    public void Directory_IsRefused()
    {
        var fs = Standard();

        var ex = Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve("/etc/hkdfguard/keys"));
        Assert.Contains("not a regular file", ex.Message);
    }

    [Fact]
    public void Device_IsRefused()
    {
        var fs = Standard().Other(KeyFile);

        Assert.Throws<UnauthorizedAccessException>(() => fs.Resolve(KeyFile));
    }

    [Fact]
    public void RelativePath_IsAnArgumentError()
    {
        Assert.Throws<ArgumentException>(() => Standard().Resolve("keys/v1.key"));
    }

    [Theory]
    [InlineData("/etc/hkdfguard", "/etc")]
    [InlineData("/etc", "/")]
    [InlineData("/", "/")]
    public void ParentOf_IsTheLexicalParent(string path, string parent)
        => Assert.Equal(parent, UnixKeyFileChecks.ParentOf(path));
}
