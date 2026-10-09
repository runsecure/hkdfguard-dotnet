using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// The macOS system calls MacOsNativeLibraryLoader's checks rely on: lstat for ownership,
/// permissions and type; geteuid; and the Security framework's static code signature check. Every
/// import uses an absolute system path, so none of them can be redirected by a search path.
/// </summary>
[SupportedOSPlatform("macos")]
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke bindings to macOS system libraries; the policy they feed is covered by MacOsNativeLibraryLoaderTests on every platform.")]
internal static unsafe partial class MacOsNative
{
    private const string LibSystem = "/usr/lib/libSystem.B.dylib";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string Security = "/System/Library/Frameworks/Security.framework/Security";

    // struct stat with 64-bit inodes (the only layout on arm64; "$INODE64" variants on x86_64):
    // st_dev int32 @0, st_mode uint16 @4, st_nlink uint16 @6, st_ino uint64 @8, st_uid uint32 @16,
    // st_gid uint32 @20. sizeof(struct stat) is 144; the buffer is larger to be safe.
    private const int StatBufferSize = 256;
    private const int ModeOffset = 4;
    private const int UidOffset = 16;
    private const int GidOffset = 20;

    private const ushort FileTypeMask = 0xF000;    // S_IFMT
    private const ushort RegularFile = 0x8000;     // S_IFREG
    private const ushort DirectoryType = 0x4000;   // S_IFDIR
    private const ushort SymbolicLink = 0xA000;    // S_IFLNK
    private const ushort PermissionMask = 0x0FFF;

    private const uint KCFStringEncodingUtf8 = 0x08000100;
    private const uint KSecCSCheckAllArchitectures = 1 << 0;
    private const uint KSecCSStrictValidate = 1 << 4;

    /// <summary>lstat: describes the path itself, never what a symbolic link points to.</summary>
    /// <exception cref="IOException">lstat failed</exception>
    public static UnixFileStatus GetStatus(string path)
    {
        var buffer = stackalloc byte[StatBufferSize];
        var result = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? lstat_inode64(path, buffer)
            : lstat(path, buffer);
        if (result != 0)
            throw new IOException($"lstat('{path}') failed with errno {Marshal.GetLastPInvokeError()}.");

        var mode = *(ushort*)(buffer + ModeOffset);
        var type = (mode & FileTypeMask) switch
        {
            RegularFile => UnixFileType.RegularFile,
            DirectoryType => UnixFileType.Directory,
            SymbolicLink => UnixFileType.SymbolicLink,
            _ => UnixFileType.Other,
        };

        return new UnixFileStatus(*(uint*)(buffer + UidOffset), *(uint*)(buffer + GidOffset), (UnixFileMode)(mode & PermissionMask), type);
    }

    public static uint GetEffectiveUserId() => geteuid();

    /// <summary>
    /// SecStaticCodeCheckValidity against <paramref name="requirementText"/>, for every architecture
    /// in the file, with strict validation.
    /// </summary>
    /// <returns>0 (errSecSuccess) if valid and satisfied, otherwise the failing OSStatus.</returns>
    public static int CheckCodeSignature(string path, string requirementText)
    {
        IntPtr url = 0, code = 0, requirementString = 0, requirement = 0;
        try
        {
            var pathBytes = Encoding.UTF8.GetBytes(path);
            fixed (byte* p = pathBytes)
                url = CFURLCreateFromFileSystemRepresentation(0, p, pathBytes.Length, 0);
            if (url == 0)
                return -1;

            var status = SecStaticCodeCreateWithPath(url, 0, out code);
            if (status != 0)
                return status;

            requirementString = CFStringCreateWithCString(0, requirementText, KCFStringEncodingUtf8);
            if (requirementString == 0)
                return -1;

            status = SecRequirementCreateWithString(requirementString, 0, out requirement);
            if (status != 0)
                return status;

            return SecStaticCodeCheckValidity(code, KSecCSCheckAllArchitectures | KSecCSStrictValidate, requirement);
        }
        finally
        {
            foreach (var reference in (ReadOnlySpan<IntPtr>)[requirement, requirementString, code, url])
            {
                if (reference != 0)
                    CFRelease(reference);
            }
        }
    }

    [LibraryImport(LibSystem, EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int lstat(string path, byte* buffer);

    [LibraryImport(LibSystem, EntryPoint = "lstat$INODE64", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int lstat_inode64(string path, byte* buffer);

    [LibraryImport(LibSystem)]
    private static partial uint geteuid();

    [LibraryImport(CoreFoundation)]
    private static partial IntPtr CFURLCreateFromFileSystemRepresentation(IntPtr allocator, byte* buffer, nint length, byte isDirectory);

    [LibraryImport(CoreFoundation, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr CFStringCreateWithCString(IntPtr allocator, string text, uint encoding);

    [LibraryImport(CoreFoundation)]
    private static partial void CFRelease(IntPtr reference);

    [LibraryImport(Security)]
    private static partial int SecStaticCodeCreateWithPath(IntPtr path, uint flags, out IntPtr staticCode);

    [LibraryImport(Security)]
    private static partial int SecRequirementCreateWithString(IntPtr text, uint flags, out IntPtr requirement);

    [LibraryImport(Security)]
    private static partial int SecStaticCodeCheckValidity(IntPtr staticCode, uint flags, IntPtr requirement);
}
