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
/// fails a check, loading fails - it never falls back to the user install. Nor does it fall back
/// when the system install merely can't be examined (lstat fails with anything but ENOENT or
/// ENOTDIR, say EACCES): only "nothing is there" counts as "not installed".</item>
/// <item><b>Path integrity.</b> No component of the path, from the file up to /, may be a symbolic
/// link, or writable by anyone other than its owner - except root-owned directories writable by
/// the wheel or admin group, as /Library's are. Every component of a system install must be owned
/// by root; of a user install, by root or the current user. So only root, or for a user install
/// the user themselves, could have put the file there.</item>
/// <item><b>Code signature.</b> The file's signature must be valid and satisfy
/// <see cref="CodeRequirement"/> - signed through Apple's CA by the HkdfGuard team.</item>
/// <item><b>What dyld loaded.</b> dlopen of an absolute path does not load exactly that path: dyld
/// first looks for the path's leaf name in every DYLD_LIBRARY_PATH directory (dlopen(3)), and the
/// dotnet host is entitled to honour DYLD_* variables despite its hardened runtime. So the loader
/// refuses before dlopen if a DYLD_LIBRARY_PATH directory holds a <see cref="FileName"/>, and
/// after dlopen asks dyld (dladdr) which file it mapped; anything but the verified path is unloaded
/// and refused. The second check is the authority; the first only stops an impostor's
/// initializers from running at all in the plain-misconfiguration case.</item>
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

    /// <summary>The library's own minimum (its LC_BUILD_VERSION minos).</summary>
    internal static readonly Version MinimumMacOsVersion = new(13, 0);

    /// <summary>An export every genuine build has; its address tells dladdr which file was loaded.</summary>
    internal const string ProbeExport = "hkdfguard_wrap_dek";

    private const int ENOENT = 2;
    private const int ENOTDIR = 20;

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

            RequireSupportedPlatform(RuntimeInformation.ProcessArchitecture, Environment.OSVersion.Version);

            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
            var (path, isSystem) = ChoosePath(MacOsNative.Probe, home);

            uint[] trustedOwners = isSystem ? [0] : [0, MacOsNative.GetEffectiveUserId()];
            VerifyLocation(path, MacOsNative.GetStatus, trustedOwners);
            VerifySignature(path, MacOsNative.CheckCodeSignature);
            RefuseShadowing(Environment.GetEnvironmentVariable, File.Exists);

            // dyld may still map a different file than the path asks for (see the class summary),
            // so the loaded image is checked and, if it isn't the verified file, unloaded. The
            // library's own dependencies are absolute system paths and need no such check.
            var handle = NativeLibrary.Load(path);
            try
            {
                var loaded = NativeLibrary.TryGetExport(handle, ProbeExport, out var export) ? MacOsNative.GetImagePath(export) : null;
                VerifyLoadedImage(path, loaded);
            }
            catch
            {
                NativeLibrary.Free(handle);
                throw;
            }

            _handle = handle;
            return _handle;
        }
    }

    /// <summary>
    /// Requires what the library itself requires: an arm64 process (the library is built for
    /// Apple silicon only, and needs its Secure Enclave) on macOS <see cref="MinimumMacOsVersion"/>
    /// or later. Checked first, so an unsupported Mac gets this explanation rather than dyld's
    /// "incompatible architecture" after every other check has passed.
    /// </summary>
    /// <param name="processArchitecture">The process's architecture - X64 under Rosetta, even on Apple silicon.</param>
    /// <param name="osVersion">The macOS version.</param>
    /// <exception cref="PlatformNotSupportedException">Either requirement is not met.</exception>
    internal static void RequireSupportedPlatform(Architecture processArchitecture, Version osVersion)
    {
        if (processArchitecture != Architecture.Arm64)
            throw new PlatformNotSupportedException(
                $"The HkdfGuard native KMS library requires Apple silicon: an arm64 process on an arm64 Mac. This process is {processArchitecture}"
                + (processArchitecture == Architecture.X64 ? " - an Intel Mac, or an x64 .NET runtime running under Rosetta; on Apple silicon, use the arm64 .NET runtime." : "."));

        if (osVersion < MinimumMacOsVersion)
            throw new PlatformNotSupportedException(
                $"The HkdfGuard native KMS library requires macOS {MinimumMacOsVersion.Major} or later; this is macOS {osVersion}.");
    }

    /// <summary>
    /// The system install if it exists, otherwise the user install if that exists. "Exists" is
    /// decided by lstat, so that "can't look" is never mistaken for "not there".
    /// </summary>
    /// <param name="probe">lstat's result for a path: 0 if it exists, else the errno.</param>
    /// <exception cref="DllNotFoundException">Neither exists.</exception>
    /// <exception cref="SecurityException">An install location could not be examined.</exception>
    internal static (string Path, bool IsSystem) ChoosePath(Func<string, int> probe, string homeDirectory)
    {
        if (IsPresent(SystemPath, probe, "system-wide"))
            return (SystemPath, true);

        var user = UserPath(homeDirectory);
        // Only an absolute home: a relative one would resolve against the working directory.
        if (homeDirectory.StartsWith('/') && IsPresent(user, probe, "per-user"))
            return (user, false);

        throw new DllNotFoundException(
            $"The HkdfGuard native KMS library is not installed. Install it at '{SystemPath}' (system-wide) or '{user}' (this user); it is never loaded from anywhere else.");
    }

    // ENOENT and ENOTDIR: nothing is installed there. Anything else (EACCES, ELOOP, EIO, ...) means
    // something may well be there that this process isn't allowed to see; a system install hidden
    // that way must not let the per-user one take its place.
    private static bool IsPresent(string path, Func<string, int> probe, string kind)
    {
        var errno = probe(path);
        if (errno == 0)
            return true;
        if (errno is ENOENT or ENOTDIR)
            return false;

        throw new SecurityException(
            $"Could not tell whether the {kind} HkdfGuard native library '{path}' exists (lstat failed with errno {errno}); refusing to guess or to fall back to another location.");
    }

    /// <summary>
    /// Refuses, before anything is loaded, if a DYLD_LIBRARY_PATH directory contains a file named
    /// <see cref="FileName"/>: dyld would load that in place of the verified path.
    /// </summary>
    /// <param name="getEnvironmentVariable">Reads an environment variable; null if unset.</param>
    /// <param name="exists">Whether a path exists.</param>
    /// <exception cref="SecurityException">A shadowing library was found.</exception>
    internal static void RefuseShadowing(Func<string, string?> getEnvironmentVariable, Func<string, bool> exists)
    {
        var searchPath = getEnvironmentVariable("DYLD_LIBRARY_PATH");
        if (string.IsNullOrEmpty(searchPath))
            return;

        foreach (var directory in searchPath.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = $"{directory.TrimEnd('/')}/{FileName}";
            if (exists(candidate))
                throw new SecurityException(
                    $"'{candidate}' is on DYLD_LIBRARY_PATH and would be loaded in place of the verified HkdfGuard native library; refusing to load. Remove it from DYLD_LIBRARY_PATH.");
        }
    }

    /// <summary>
    /// Requires that the file dyld reports having loaded is the one that was verified.
    /// </summary>
    /// <param name="expectedPath">The verified path that was passed to dlopen.</param>
    /// <param name="loadedPath">The path dladdr reports for the loaded library's export, or null if it has no such export or dyld can't say.</param>
    /// <exception cref="SecurityException">They differ.</exception>
    internal static void VerifyLoadedImage(string expectedPath, string? loadedPath)
    {
        if (loadedPath is null)
            throw new SecurityException(
                $"The library loaded for '{expectedPath}' has no '{ProbeExport}' export, or dyld cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.");

        if (loadedPath != expectedPath)
            throw new SecurityException(
                $"dyld loaded '{loadedPath}' in place of the verified '{expectedPath}' (DYLD_LIBRARY_PATH, most likely); it has been unloaded and the HkdfGuard native library was not loaded.");
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
