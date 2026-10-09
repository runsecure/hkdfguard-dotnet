using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Loads the macOS native KMS library from one of its two install locations and nowhere else.
/// The library receives every plaintext DEK on unwrap and chooses every "random" DEK on
/// generate-and-wrap, so loading an impostor would hand over every key. The default probe would
/// honour DYLD_LIBRARY_PATH and the application directory; this loader replaces it.
/// <list type="number">
/// <item><b>Location.</b> The system install, <see cref="SystemDirectory"/>, is used whenever it
/// exists; the per-user install, <c>~/.hkdfguard/v1</c>, only when there is no system install.
/// That order matters: anything running as the user can write to the user's home, so a per-user
/// file must never be able to override a root-owned system one. If the system install exists but
/// fails a check, loading fails - it never falls back to the user install.</item>
/// <item><b>Path integrity.</b> No component of the path, from the file up to /, may be a symbolic
/// link, or writable by anyone other than its owner - except root-owned directories writable by
/// the wheel or admin group, as /Library's are. Every component of a system install must be owned
/// by root; of a user install, by root or the current user. So only root, or for a user install
/// the user themselves, could have put the file there.</item>
/// <item><b>Code signature.</b> The file's signature must be valid and satisfy
/// <see cref="CodeRequirement"/> - signed through Apple's CA by the HkdfGuard team.</item>
/// </list>
/// Any failed check throws; there is deliberately no other fallback and no override.
/// </summary>
internal static class MacOsNativeLibraryLoader
{
    internal const string FileName = "libhkdfguard_v1.dylib";

    /// <summary>The system-wide install, used whenever it exists.</summary>
    internal const string SystemDirectory = "/Library/Application Support/HkdfGuard/v1";

    /// <summary>The per-user install, relative to the user's home directory.</summary>
    internal const string UserDirectoryUnderHome = ".hkdfguard/v1";

    /// <summary>
    /// The Apple team ID the library must be signed by: the certificate's subject OU (and
    /// codesign's TeamIdentifier) - not the personal ID in an Apple Development certificate's CN.
    /// </summary>
    internal const string TeamId = "MFW3T8R8J3";

    /// <summary>
    /// The code requirement the library's signature must satisfy, matching the release build's own
    /// designated requirement: this library's identifier, signed with a Developer ID Application
    /// certificate (not Apple Development) issued to the HkdfGuard team. So a development build, or
    /// any other binary the team signs (such as hkdfguard-v1-initialize), is refused.
    /// </summary>
    internal const string CodeRequirement =
        "identifier \"libhkdfguard_v1\" and anchor apple generic"
        + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"    // Developer ID CA
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" // Developer ID Application leaf
        + $" and certificate leaf[subject.OU] = \"{TeamId}\"";

    // gid 0 (wheel) and 80 (admin): on macOS, root-owned system directories such as
    // /Library/Application Support may be writable by these groups. Both are administrators.
    private static readonly uint[] AdministrativeGroups = [0, 80];

    private static readonly Lock Gate = new();
    private static IntPtr _handle;

    /// <summary>The system install's full path.</summary>
    internal static string SystemPath => $"{SystemDirectory}/{FileName}";

    /// <summary>The per-user install's full path under <paramref name="homeDirectory"/>.</summary>
    internal static string UserPath(string homeDirectory) => $"{homeDirectory.TrimEnd('/')}/{UserDirectoryUnderHome}/{FileName}";

    /// <summary>
    /// Verifies and loads the installed library, once per process; later calls return the same
    /// handle. A failure isn't cached, so a fixed installation is picked up on the next call.
    /// </summary>
    /// <exception cref="DllNotFoundException">The library is installed at neither location.</exception>
    /// <exception cref="SecurityException">The installed file or its location failed verification.</exception>
    [SupportedOSPlatform("macos")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered policy methods to macOS system calls; runs only on macOS.")]
    public static IntPtr Load()
    {
        lock (Gate)
        {
            if (_handle != IntPtr.Zero)
                return _handle;

            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
            var (path, isSystem) = ChoosePath(File.Exists, home);

            uint[] trustedOwners = isSystem ? [0] : [0, MacOsNative.GetEffectiveUserId()];
            VerifyLocation(path, MacOsNative.GetStatus, trustedOwners);
            VerifySignature(path, MacOsNative.CheckCodeSignature);

            // An absolute path: dlopen loads exactly this file. Its own dependencies are absolute
            // system paths (/usr/lib, /System/Library), so no search path applies to them either.
            _handle = NativeLibrary.Load(path);
            return _handle;
        }
    }

    /// <summary>
    /// The system install if it exists, otherwise the user install if that exists.
    /// </summary>
    /// <exception cref="DllNotFoundException">Neither exists.</exception>
    internal static (string Path, bool IsSystem) ChoosePath(Func<string, bool> exists, string homeDirectory)
    {
        if (exists(SystemPath))
            return (SystemPath, true);

        var user = UserPath(homeDirectory);
        // Only an absolute home: a relative one would resolve against the working directory.
        if (homeDirectory.StartsWith('/') && exists(user))
            return (user, false);

        throw new DllNotFoundException(
            $"The HkdfGuard native KMS library is not installed. Install it at '{SystemPath}' (system-wide) or '{user}' (this user); it is never loaded from anywhere else.");
    }

    /// <summary>
    /// Checks the file and every parent directory up to /: not a symbolic link, owned by one of
    /// <paramref name="trustedOwners"/>, and not writable by anyone else.
    /// </summary>
    /// <exception cref="SecurityException">A path component failed a check.</exception>
    internal static void VerifyLocation(string path, Func<string, UnixFileStatus> getStatus, IReadOnlyCollection<uint> trustedOwners)
    {
        var file = getStatus(path);
        if (file.Type != UnixFileType.RegularFile)
            throw new SecurityException($"'{path}' is not a regular file (it is a {Describe(file.Type)}).");
        VerifyComponent(path, file, trustedOwners);

        for (var directory = ParentOf(path); directory is not null; directory = ParentOf(directory))
        {
            var status = getStatus(directory);
            if (status.Type != UnixFileType.Directory)
                throw new SecurityException($"'{directory}' is not a directory (it is a {Describe(status.Type)}); the library is only loaded through a real path.");
            VerifyComponent(directory, status, trustedOwners);
        }
    }

    internal static void VerifyComponent(string path, UnixFileStatus status, IReadOnlyCollection<uint> trustedOwners)
    {
        // Root owns the system directories above every install (/, /Library, /Users).
        if (status.OwnerId != 0 && !trustedOwners.Contains(status.OwnerId))
            throw new SecurityException(
                $"'{path}' is owned by uid {status.OwnerId}; the HkdfGuard native library is only loaded from a location owned by {DescribeOwners(trustedOwners)}.");

        if (status.Permissions.HasFlag(UnixFileMode.OtherWrite))
            throw new SecurityException($"'{path}' is writable by every user; the HkdfGuard native library is only loaded from a location only its owner can modify.");

        if (status.Permissions.HasFlag(UnixFileMode.GroupWrite)
            && !(status.OwnerId == 0 && AdministrativeGroups.Contains(status.GroupId)))
            throw new SecurityException(
                $"'{path}' is writable by group {status.GroupId}; the HkdfGuard native library is only loaded from a location only its owner (or, for a root-owned directory, administrators) can modify.");
    }

    /// <summary>Requires a valid code signature that satisfies <see cref="CodeRequirement"/>.</summary>
    /// <param name="path">The library.</param>
    /// <param name="checkSignature">Returns 0 (errSecSuccess) when the signature is valid and satisfies the requirement, else the OSStatus.</param>
    /// <exception cref="SecurityException">The signature is missing, invalid, or from another team.</exception>
    internal static void VerifySignature(string path, Func<string, string, int> checkSignature)
    {
        var status = checkSignature(path, CodeRequirement);
        if (status != 0)
            throw new SecurityException(
                $"'{path}' is not validly signed by the HkdfGuard team ({TeamId}); code signature check failed with OSStatus {status}.");
    }

    // macOS paths are always '/'-separated, whatever platform runs the tests. Null above /.
    internal static string? ParentOf(string path)
    {
        if (path == "/")
            return null;

        var slash = path.TrimEnd('/').LastIndexOf('/');
        return slash <= 0 ? "/" : path[..slash];
    }

    private static string Describe(UnixFileType type) => type switch
    {
        UnixFileType.SymbolicLink => "symbolic link",
        UnixFileType.Directory => "directory",
        UnixFileType.RegularFile => "regular file",
        _ => "special file",
    };

    private static string DescribeOwners(IReadOnlyCollection<uint> trustedOwners)
        => trustedOwners.Count == 1 ? "root" : "root or the current user";
}
