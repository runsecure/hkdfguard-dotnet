using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// The Linux system calls LinuxNativeLibraryLoader's checks rely on: statx (without following
/// symbolic links) for ownership, permissions and type; readlink; dladdr for which file the dynamic
/// linker really mapped; and dlopen(RTLD_NOLOAD) with dlinfo for where an already-loaded
/// dependency came from. Every import is in glibc's libc.so.6 (2.34 or later, which the native
/// package itself requires). The process has already loaded libc.so.6, and the dynamic linker
/// matches an already-loaded library by name before it searches anywhere, so LD_LIBRARY_PATH
/// cannot substitute it.
/// </summary>
[SupportedOSPlatform("linux")]
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke bindings to glibc; the policy they feed is covered by LinuxNativeLibraryLoaderTests on every platform, and these run against the real filesystem in its Linux-only tests.")]
internal static unsafe partial class LinuxNative
{
    private const string LibC = "libc.so.6";

    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;

    // struct statx has one layout on every architecture: stx_mask u32 @0, stx_uid u32 @20,
    // stx_gid u32 @24, stx_mode u16 @28. sizeof(struct statx) is 256.
    private const int StatxBufferSize = 256;
    private const int MaskOffset = 0;
    private const int UidOffset = 20;
    private const int GidOffset = 24;
    private const int ModeOffset = 28;
    private const uint StatxType = 0x1, StatxMode = 0x2, StatxUid = 0x8, StatxGid = 0x10;
    private const uint StatxRequired = StatxType | StatxMode | StatxUid | StatxGid;

    private const ushort FileTypeMask = 0xF000;  // S_IFMT
    private const ushort RegularFile = 0x8000;   // S_IFREG
    private const ushort DirectoryType = 0x4000; // S_IFDIR
    private const ushort SymbolicLink = 0xA000;  // S_IFLNK
    private const ushort PermissionMask = 0x0FFF;

    private const int ENOENT = 2;
    private const int ENOTDIR = 20;

    private const int RtldLazy = 0x1;
    private const int RtldNoLoad = 0x4;
    private const int RtldDiLinkMap = 2;

    /// <summary>
    /// Describes the path itself, never what a symbolic link points to. Null when nothing is there
    /// (ENOENT or ENOTDIR).
    /// </summary>
    /// <exception cref="IOException">statx failed for any other reason, such as EACCES.</exception>
    public static UnixFileStatus? GetStatusOrNull(string path)
    {
        var errno = TryGetStatus(path, out var status);
        if (errno == 0)
            return status;
        if (errno is ENOENT or ENOTDIR)
            return null;

        throw new IOException($"statx('{path}') failed with errno {errno}.");
    }

    /// <summary>The errno of a failed statx on a path whose existence is only being probed; 0 if it exists.</summary>
    public static int Probe(string path) => TryGetStatus(path, out _);

    private static int TryGetStatus(string path, out UnixFileStatus status)
    {
        var buffer = stackalloc byte[StatxBufferSize];
        if (statx(AtFdCwd, path, AtSymlinkNoFollow, StatxRequired, buffer) != 0)
        {
            status = default;
            return Marshal.GetLastPInvokeError();
        }

        if ((*(uint*)(buffer + MaskOffset) & StatxRequired) != StatxRequired)
            throw new IOException($"statx('{path}') did not report the file's type, mode and owner.");

        var mode = *(ushort*)(buffer + ModeOffset);
        var type = (mode & FileTypeMask) switch
        {
            RegularFile => UnixFileType.RegularFile,
            DirectoryType => UnixFileType.Directory,
            SymbolicLink => UnixFileType.SymbolicLink,
            _ => UnixFileType.Other,
        };

        status = new UnixFileStatus(*(uint*)(buffer + UidOffset), *(uint*)(buffer + GidOffset), (UnixFileMode)(mode & PermissionMask), type);
        return 0;
    }

    /// <summary>A symbolic link's target, exactly as stored (possibly relative), or null if it isn't one.</summary>
    public static string? ReadLink(string path) => new FileInfo(path).LinkTarget;

    /// <summary>
    /// dladdr: the path the dynamic linker recorded for the object containing
    /// <paramref name="address"/>, or null if it doesn't know the address.
    /// </summary>
    public static string? GetImagePath(IntPtr address)
    {
        // Dl_info: dli_fname, dli_fbase, dli_sname, dli_saddr - four pointers.
        var info = stackalloc IntPtr[4];
        return dladdr(address, info) != 0 ? Marshal.PtrToStringUTF8(info[0]) : null;
    }

    /// <summary>
    /// The path the dynamic linker recorded for the already-loaded object it would bind
    /// <paramref name="soname"/> to, or null if no such object is loaded. Never loads anything.
    /// </summary>
    public static string? GetLoadedPath(string soname)
    {
        var handle = dlopen(soname, RtldLazy | RtldNoLoad);
        if (handle == 0)
            return null;

        try
        {
            // struct link_map: l_addr, l_name, ... - l_name is the second pointer.
            IntPtr map;
            if (dlinfo(handle, RtldDiLinkMap, &map) != 0 || map == 0)
                return null;

            return Marshal.PtrToStringUTF8(*(IntPtr*)(map + IntPtr.Size));
        }
        finally
        {
            // RTLD_NOLOAD still took a reference; give it back.
            _ = dlclose(handle);
        }
    }

    /// <summary>
    /// The process's environment as it was at exec, which is what the dynamic linker read, or null
    /// if /proc/self/environ can't be read.
    /// </summary>
    public static byte[]? ReadInitialEnvironment()
    {
        try
        {
            return File.ReadAllBytes("/proc/self/environ");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [LibraryImport(LibC, EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int statx(int dirfd, string path, int flags, uint mask, byte* buffer);

    [LibraryImport(LibC)]
    private static partial int dladdr(IntPtr address, IntPtr* info);

    [LibraryImport(LibC, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr dlopen(string file, int mode);

    [LibraryImport(LibC)]
    private static partial int dlinfo(IntPtr handle, int request, IntPtr* info);

    [LibraryImport(LibC)]
    private static partial int dlclose(IntPtr handle);
}
