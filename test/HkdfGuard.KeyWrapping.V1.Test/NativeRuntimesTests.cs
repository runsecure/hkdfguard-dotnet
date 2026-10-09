using System.Security.Cryptography;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Guards any native release artifacts present under src/HkdfGuard.KeyWrapping.V1/runtimes: every
/// file a SHA256SUMS lists must exist and match byte for byte (a line-ending conversion on checkout
/// is enough to break one), and a macOS build must be the file name MacOsNativeLibraryLoader loads.
/// runtimes folders are git-ignored, so the folder may be absent - then there is nothing to check.
/// </summary>
public class NativeRuntimesTests
{
    private static IEnumerable<string> RuntimeFolders()
        => Directory.Exists(RuntimesRoot) ? Directory.GetDirectories(RuntimesRoot) : [];

    [Fact]
    public void EveryFileListedInSha256Sums_MatchesItsHash()
    {
        foreach (var folder in RuntimeFolders())
        {
            var sumsPath = Path.Combine(folder, "SHA256SUMS");
            if (!File.Exists(sumsPath))
                continue;

            var sums = File.ReadAllLines(sumsPath).Where(line => line.Length > 0).ToList();
            Assert.NotEmpty(sums);

            foreach (var line in sums)
            {
                Assert.DoesNotContain('\r', line);
                var parts = line.Split("  ", 2);
                var actual = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(folder, parts[1]))));
                Assert.True(parts[0] == actual, $"{Path.GetFileName(folder)}/{parts[1]}: SHA256SUMS says {parts[0]}, file is {actual}");
            }
        }
    }

    [Fact]
    public void AMacOsBuild_IsNamedAsTheLoaderExpects()
    {
        foreach (var folder in RuntimeFolders().Where(f => Path.GetFileName(f).StartsWith("osx-", StringComparison.Ordinal)))
            Assert.True(File.Exists(Path.Combine(folder, MacOsNativeLibraryLoader.FileName)), $"{folder} has no {MacOsNativeLibraryLoader.FileName}");
    }

    private static string RuntimesRoot
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "HkdfGuard.sln")))
                dir = dir.Parent;

            Assert.NotNull(dir);
            return Path.Combine(dir.FullName, "src", "HkdfGuard.KeyWrapping.V1", "runtimes");
        }
    }
}
