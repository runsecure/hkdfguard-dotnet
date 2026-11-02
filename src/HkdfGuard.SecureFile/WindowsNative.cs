using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace HkdfGuard.SecureFile;

/// <summary>
/// GetFinalPathNameByHandleW: the path of the file a handle actually refers to, after every
/// symbolic link, junction, mount point and substituted drive has been resolved, in long-name
/// form. WindowsKeyFileChecks compares it with the path that was asked for.
/// </summary>
[SupportedOSPlatform("windows")]
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to kernel32; the policy it feeds is covered by WindowsKeyFileChecksTests, and it runs against real files in its Windows-only tests.")]
internal static unsafe partial class WindowsNative
{
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    private const uint Flags = 0;

    /// <exception cref="IOException">The path could not be read from the handle.</exception>
    public static string GetFinalPath(SafeFileHandle handle)
    {
        var buffer = new char[512];
        while (true)
        {
            uint length;
            fixed (char* path = buffer)
                length = GetFinalPathNameByHandleW(handle, path, (uint)buffer.Length, Flags);

            if (length == 0)
                throw new IOException("Could not read the opened file's final path.", new Win32Exception(Marshal.GetLastPInvokeError()));
            if (length < buffer.Length)
                return new string(buffer, 0, (int)length);

            // Too small: length is the size needed, terminator included.
            buffer = new char[length];
        }
    }

    // System32 only: the runtime's default would try kernel32.dll beside this assembly first.
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);
}
