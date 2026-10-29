using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HkdfGuard.SecureFile;

/// <summary>
/// The one system call UnixKeyFileChecks needs that .NET doesn't expose: the owner, group,
/// permissions and type of a path itself, never what a symbolic link points to. Linux uses statx
/// from glibc's libc.so.6 (2.28 or later), whose struct has one layout on every architecture; macOS
/// uses lstat from libSystem, on arm64 only, whose struct stat this reads.
/// </summary>
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke bindings to libc; the policy they feed is covered by UnixKeyFileChecksTests on every platform, and these run against the real filesystem in its Unix-only tests.")]
internal static unsafe partial class UnixNative
{
    private const string LinuxLibC = "libc.so.6";
    private const string MacOsLibSystem = "/usr/lib/libSystem.B.dylib";

    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;

    // struct statx: stx_mask u32 @0, stx_uid u32 @20, stx_gid u32 @24, stx_mode u16 @28; 256 bytes.
    private const int StatxBufferSize = 256;
    private const uint StatxType = 0x1, StatxMode = 0x2, StatxUid = 0x8, StatxGid = 0x10;
    private const uint StatxRequired = StatxType | StatxMode | StatxUid | StatxGid;

    // macOS arm64 struct stat: st_mode u16 @4, st_uid u32 @16, st_gid u32 @20; 144 bytes.
    private const int StatBufferSize = 256;

    private const ushort FileTypeMask = 0xF000;  // S_IFMT
    private const ushort RegularFile = 0x8000;   // S_IFREG
    private const ushort DirectoryType = 0x4000; // S_IFDIR
    private const ushort SymbolicLink = 0xA000;  // S_IFLNK
    private const ushort PermissionMask = 0x0FFF;

    private const int ENOENT = 2;
    private const int EACCES = 13;
    private const int ENOTDIR = 20;

    /// <summary>
    /// Describes the path itself, never what a symbolic link points to. Null when nothing is there
    /// (ENOENT or ENOTDIR).
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">This account may not look (EACCES).</exception>
    /// <exception cref="IOException">The call failed for any other reason.</exception>
    /// <exception cref="PlatformNotSupportedException">macOS on an Intel processor.</exception>
    public static UnixFileStatus? GetStatusOrNull(string path)
    {
        var errno = OperatingSystem.IsLinux() ? LinuxStatus(path, out var status) : MacOsStatus(path, out status);
        return errno switch
        {
            0 => status,
            ENOENT or ENOTDIR => null,
            EACCES => throw new UnauthorizedAccessException($"This account may not look up '{path}' (EACCES)."),
            _ => throw new IOException($"Could not look up '{path}' (errno {errno})."),
        };
    }

    /// <summary>A symbolic link's target, exactly as stored (possibly relative).</summary>
    public static string? ReadLink(string path) => new FileInfo(path).LinkTarget;

    private static int LinuxStatus(string path, out UnixFileStatus status)
    {
        var buffer = stackalloc byte[StatxBufferSize];
        if (statx(AtFdCwd, path, AtSymlinkNoFollow, StatxRequired, buffer) != 0)
        {
            status = default;
            return Marshal.GetLastPInvokeError();
        }

        if ((*(uint*)buffer & StatxRequired) != StatxRequired)
            throw new IOException($"statx('{path}') did not report the file's type, mode and owner.");

        status = Decode(*(ushort*)(buffer + 28), *(uint*)(buffer + 20), *(uint*)(buffer + 24));
        return 0;
    }

    private static int MacOsStatus(string path, out UnixFileStatus status)
    {
        // The x86_64 "lstat" symbol fills a different, older struct; Intel Macs aren't supported.
        if (RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
            throw new PlatformNotSupportedException(
                $"Trusted files are read on Apple silicon Macs only; this process is {RuntimeInformation.ProcessArchitecture}.");

        var buffer = stackalloc byte[StatBufferSize];
        if (lstat(path, buffer) != 0)
        {
            status = default;
            return Marshal.GetLastPInvokeError();
        }

        status = Decode(*(ushort*)(buffer + 4), *(uint*)(buffer + 16), *(uint*)(buffer + 20));
        return 0;
    }

    private static UnixFileStatus Decode(ushort mode, uint uid, uint gid)
    {
        var type = (mode & FileTypeMask) switch
        {
            RegularFile => UnixFileType.RegularFile,
            DirectoryType => UnixFileType.Directory,
            SymbolicLink => UnixFileType.SymbolicLink,
            _ => UnixFileType.Other,
        };
        return new UnixFileStatus(uid, gid, (UnixFileMode)(mode & PermissionMask), type);
    }

    // Without AssemblyDirectory the runtime calls dlopen with the bare name, which matches the
    // libc.so.6 the process already has; its default would first try one beside this assembly by
    // absolute path, which a copy planted in the application folder could answer. (lstat below is
    // already an absolute path.)
    [LibraryImport(LinuxLibC, EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    private static partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport(MacOsLibSystem, EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int lstat(string path, byte* buffer);
}
