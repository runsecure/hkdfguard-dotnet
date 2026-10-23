using System.Runtime.Versioning;
using System.Security.Principal;

namespace HkdfGuard.SecureFile.Test.TestHelpers;

/// <summary>
/// A fresh folder under the user's temp folder, named by its long path: Windows may report the
/// temp folder by an 8.3 short name (C:\Users\RUNNER~1\... on hosted runners), which key files
/// are never read through.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsTempDirectory : IDisposable
{
    public static KeyFileTrust TrustCurrentUser { get; } =
        new() { WindowsPrincipals = [WindowsIdentity.GetCurrent().User!.Value] };

    public WindowsTempDirectory()
        => Path = LongPath(Directory.CreateTempSubdirectory("hkdfguard-keys-").FullName);

    public string Path { get; }

    public string Write(string name, byte[] contents)
    {
        var path = System.IO.Path.Combine(Path, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    public void Dispose() => Directory.Delete(Path, recursive: true);

    /// <summary>Each component's real (long) name, as the folder lists it.</summary>
    public static string LongPath(string path)
    {
        var full = System.IO.Path.GetFullPath(path);
        var root = System.IO.Path.GetPathRoot(full)!;
        var current = new DirectoryInfo(root);
        foreach (var name in full[root.Length..].Split(System.IO.Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            current = current.EnumerateDirectories(name).Single();
        return current.FullName;
    }

    /// <summary>The path with each component's 8.3 short name, where the volume keeps them.</summary>
    public static string ShortPath(string path)
    {
        var buffer = new char[1024];
        var length = GetShortPathNameW(path, buffer, buffer.Length);
        return length > 0 && length < buffer.Length ? new string(buffer, 0, length) : path;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int GetShortPathNameW(string longPath, [System.Runtime.InteropServices.Out] char[] shortPath, int length);
}
