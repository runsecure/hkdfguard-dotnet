using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

/// <summary>
/// Temporary folders for key files the native library reads. hkdfguard_open_file refuses an 8.3
/// short name anywhere in a path, and Windows can hand out %TEMP% in short form (for example
/// C:\Users\RUNNER~1\... on GitHub-hosted runners), so on Windows the folder's long path is used.
/// </summary>
internal static partial class TestDirectories
{
    public static string CreateTemp(string prefix)
    {
        var path = Directory.CreateTempSubdirectory(prefix).FullName;
        if (!OperatingSystem.IsWindows())
            return path;

        var buffer = new char[32_767];
        var length = GetLongPathNameW(path, buffer, buffer.Length);
        return length > 0 && length < buffer.Length ? new string(buffer, 0, (int)length) : path;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint GetLongPathNameW(string shortPath, [Out] char[] longPath, int bufferLength);
}
