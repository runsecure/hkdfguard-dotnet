using System.Reflection;
using System.Runtime.InteropServices;
using HkdfGuard.SecureFile;

namespace HkdfGuard.SecureFile.Test;

/// <summary>
/// The system calls the key-file checks make must reach the system's own libraries, never a copy
/// beside this assembly, which the runtime's default probe tries first: a planted kernel32.dll or
/// libc.so.6 there could report any file as trusted. A bare-name import therefore needs
/// DefaultDllImportSearchPaths without AssemblyDirectory; an absolute path needs nothing.
/// </summary>
public class NativeImportSearchPathTests
{
    [Fact]
    public void EveryBareNameSystemImport_SkipsTheAssemblyDirectory()
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;
        var offenders = new List<string>();
        var imports = 0;
        foreach (var type in typeof(TrustedKeyFile).Assembly.GetTypes())
        {
            foreach (var method in type.GetMethods(All))
            {
                var import = method.GetCustomAttribute<LibraryImportAttribute>();
                if (import is null)
                    continue;
                imports++;
                if (Path.IsPathRooted(import.LibraryName))
                    continue;
                var searchPaths = method.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>();
                if (searchPaths is null || searchPaths.Paths.HasFlag(DllImportSearchPath.AssemblyDirectory))
                    offenders.Add($"{type.Name}.{method.Name} ({import.LibraryName})");
            }
        }

        Assert.True(imports > 0, "found no [LibraryImport] at all; the test is no longer looking at the right assembly");
        Assert.Empty(offenders);
    }
}
