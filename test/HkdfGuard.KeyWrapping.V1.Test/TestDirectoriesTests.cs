using System.Runtime.Versioning;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// TestDirectories.CreateKeyFileDirectory on Linux: the folder every Linux test that hands a key
/// file to the native library (or to hkdfguard wrap) writes it in. The library refuses a key file
/// below any group- or other-writable directory, sticky or not, so the folder must be private and
/// every directory above it trusted - never under /tmp, /var/tmp or /dev/shm. Skipped off Linux,
/// and (with the reason) where no such folder can be made.
/// </summary>
[SupportedOSPlatform("linux")]
public class TestDirectoriesTests
{
    [LinuxFact(NeedsKeyFileDirectory = true)]
    public void TheKeyFileDirectory_IsPrivate_AndEveryDirectoryAboveItIsTrusted()
    {
        var directory = TestDirectories.CreateKeyFileDirectory("hkdfguard-helper-");
        try
        {
            Assert.Null(TestDirectories.UntrustedDirectoryInChain(directory));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(directory));

            foreach (var shared in new[] { "/tmp", "/var/tmp", "/dev/shm", Path.TrimEndingDirectorySeparator(Path.GetTempPath()) })
                Assert.False(directory == shared || directory.StartsWith(shared + "/", StringComparison.Ordinal), $"{directory} is under {shared}.");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [LinuxFact]
    public void TheStickyWorldWritableTempDirectory_IsNotTrusted()
    {
        // The sticky bit earns /tmp no exception: anything under it is refused.
        var problem = TestDirectories.UntrustedDirectoryInChain("/tmp");

        Assert.NotNull(problem);
        Assert.Contains("'/tmp'", problem);
    }

    [LinuxFact]
    public void ARelativePath_IsNotTrusted()
        => Assert.NotNull(TestDirectories.UntrustedDirectoryInChain("relative/folder"));
}
