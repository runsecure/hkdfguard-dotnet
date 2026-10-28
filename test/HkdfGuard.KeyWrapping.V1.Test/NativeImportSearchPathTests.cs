using System.Reflection;
using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Every system library the loader's own checks call into must be found where the system keeps
/// it, never beside this assembly: the runtime's default probe tries the assembly directory first,
/// and a planted copy there could answer every ownership, signature and dladdr check. A bare-name
/// import therefore needs DefaultDllImportSearchPaths without AssemblyDirectory. Absolute paths
/// need nothing, and the KMS library names are routed by NativeLibraryResolver, never probed.
/// </summary>
public class NativeImportSearchPathTests
{
    private static readonly string[] ResolverRouted =
        [WindowsHkdfGuardKmsLibrary.LibraryName, LinuxHkdfGuardKmsLibrary.LibraryName, MacOsHkdfGuardKmsLibrary.LibraryName];

    [Fact]
    public void EveryBareNameSystemImport_SkipsTheAssemblyDirectory()
    {
        var offenders = BareNameImportsProbingTheAssemblyDirectory(typeof(NativeHkdfKeyWrapperV1).Assembly, ResolverRouted);

        Assert.Empty(offenders);
    }

    /// <summary>
    /// "Type.Method (library)" for every [LibraryImport] in <paramref name="assembly"/> naming a
    /// library by bare name, not in <paramref name="exempt"/>, without a
    /// DefaultDllImportSearchPaths that leaves out AssemblyDirectory.
    /// </summary>
    internal static List<string> BareNameImportsProbingTheAssemblyDirectory(Assembly assembly, IReadOnlyCollection<string> exempt)
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;
        var offenders = new List<string>();
        foreach (var type in assembly.GetTypes())
        {
            foreach (var method in type.GetMethods(All))
            {
                var import = method.GetCustomAttribute<LibraryImportAttribute>();
                if (import is null || Path.IsPathRooted(import.LibraryName) || exempt.Contains(import.LibraryName))
                    continue;
                var searchPaths = method.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>();
                if (searchPaths is null || searchPaths.Paths.HasFlag(DllImportSearchPath.AssemblyDirectory))
                    offenders.Add($"{type.Name}.{method.Name} ({import.LibraryName})");
            }
        }
        return offenders;
    }
}
