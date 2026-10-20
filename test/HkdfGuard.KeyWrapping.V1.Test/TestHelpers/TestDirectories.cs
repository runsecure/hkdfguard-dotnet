using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

/// <summary>
/// Folders for key files the native library reads (through hkdfguard_open_file) or hkdfguard
/// writes. Each platform's library refuses some locations a plain temporary folder can be in:
/// <list type="bullet">
/// <item>Windows refuses an 8.3 short name anywhere in a path, and can hand out %TEMP% in short form
/// (for example C:\Users\RUNNER~1\... on GitHub-hosted runners), so there the folder's long path is
/// used.</item>
/// <item>Linux refuses (HKDFGUARD_ERR_FILE_UNTRUSTED, -39) a key file with any group- or
/// other-writable directory above it, sticky or not - so anything under /tmp, /var/tmp or /dev/shm.
/// There the folder is a private (0700) one under a trusted root: $XDG_RUNTIME_DIR when it is set
/// and trusted, otherwise ~/.cache/hkdfguard-tests (or ~/.hkdfguard-tests, where ~/.cache itself
/// is group-writable). A test that needs one is skipped, with
/// <see cref="KeyFileDirectorySkipReason"/>, when neither is usable - never passed.</item>
/// <item>macOS keeps the plain temporary folder.</item>
/// </list>
/// </summary>
internal static partial class TestDirectories
{
    private const string LinuxRootName = "hkdfguard-tests";

    private const UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    [SupportedOSPlatform("linux")]
    private static readonly Lazy<(string? Root, string? SkipReason)> LinuxRoot = new(ResolveLinuxRoot);

    /// <summary>
    /// Why a test that needs <see cref="CreateKeyFileDirectory"/> can't run here, or null when it
    /// can. Only ever non-null on Linux.
    /// </summary>
    public static string? KeyFileDirectorySkipReason => OperatingSystem.IsLinux() ? LinuxRoot.Value.SkipReason : null;

    /// <summary>
    /// Writes a key file the way hkdfguard wrap does: readable and writable by its owner only
    /// (0600), whatever the process's umask, replacing any existing file's contents and mode. The
    /// Linux library refuses (-39) a key file another account could rewrite, and an Ubuntu desktop
    /// session's umask of 002 would otherwise leave a .NET-written file group-writable.
    /// </summary>
    public static async Task WriteKeyFileAsync(string path, ReadOnlyMemory<byte> contents)
    {
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = OwnerOnlyFileMode;

        await using (var stream = new FileStream(path, options))
            await stream.WriteAsync(contents);

        // UnixCreateMode applies only when the file is created; an existing one keeps its mode.
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, OwnerOnlyFileMode);
    }

    private const UnixFileMode OwnerOnlyFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>A new, empty folder the native library will read key files from on this platform.</summary>
    public static string CreateKeyFileDirectory(string prefix)
    {
        if (OperatingSystem.IsLinux())
            return CreateLinuxPrivateDirectory(prefix);

        var path = Directory.CreateTempSubdirectory(prefix).FullName;
        if (!OperatingSystem.IsWindows())
            return path;

        var buffer = new char[32_767];
        var length = GetLongPathNameW(path, buffer, buffer.Length);
        return length > 0 && length < buffer.Length ? new string(buffer, 0, (int)length) : path;
    }

    [SupportedOSPlatform("linux")]
    private static string CreateLinuxPrivateDirectory(string prefix)
    {
        var (root, skipReason) = LinuxRoot.Value;
        if (root is null)
            throw new InvalidOperationException($"No trusted folder for key files: {skipReason} Gate the test on {nameof(KeyFileDirectorySkipReason)}.");

        var path = Path.Combine(root, prefix + Path.GetRandomFileName().Replace(".", string.Empty, StringComparison.Ordinal));
        Directory.CreateDirectory(path, PrivateDirectoryMode);
        File.SetUnixFileMode(path, PrivateDirectoryMode); // whatever the umask

        if (UntrustedDirectoryInChain(path) is { } problem)
            throw new InvalidOperationException($"'{path}' is not a trusted key file folder: {problem}");
        return path;
    }

    /// <summary>
    /// The Linux library's rule for the folders above a key file: why <paramref name="directory"/>
    /// or any directory up its chain to / isn't trusted, or null when they all are. Each must be a
    /// real directory (not a symbolic link), owned by root or this user, and neither group- nor
    /// other-writable - with no exception for the sticky bit.
    /// </summary>
    [SupportedOSPlatform("linux")]
    internal static string? UntrustedDirectoryInChain(string directory)
    {
        if (!Path.IsPathFullyQualified(directory))
            return $"'{directory}' is not an absolute path.";

        var user = geteuid();
        for (var current = Path.TrimEndingDirectorySeparator(directory); current is not null; current = Path.GetDirectoryName(current))
        {
            UnixFileStatus? status;
            try
            {
                status = LinuxNative.GetStatusOrNull(current);
            }
            catch (IOException ex)
            {
                return ex.Message;
            }

            if (status is not { } s)
                return $"'{current}' does not exist.";
            if (s.Type != UnixFileType.Directory)
                return $"'{current}' is {(s.Type == UnixFileType.SymbolicLink ? "a symbolic link" : "not a directory")}.";
            if (s.OwnerId != 0 && s.OwnerId != user)
                return $"'{current}' is owned by uid {s.OwnerId}, neither root nor this user (uid {user}).";
            if ((s.Permissions & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
                return $"'{current}' is group- or other-writable (mode {Convert.ToString((int)s.Permissions & 0xFFF, 8)}).";
        }

        return null;
    }

    /// <summary>
    /// The folder this process's key file folders go in: $XDG_RUNTIME_DIR/hkdfguard-tests when
    /// $XDG_RUNTIME_DIR is set and trusted, otherwise ~/.cache/hkdfguard-tests, otherwise
    /// ~/.hkdfguard-tests - each missing directory created 0700, and used only if every directory
    /// up its chain passes the library's rule.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static (string? Root, string? SkipReason) ResolveLinuxRoot()
    {
        var rejected = new List<string>();

        foreach (var (variable, relative) in new[]
                 {
                     ("XDG_RUNTIME_DIR", LinuxRootName),
                     ("HOME", Path.Combine(".cache", LinuxRootName)),
                     ("HOME", "." + LinuxRootName),
                 })
        {
            if (Environment.GetEnvironmentVariable(variable) is not { Length: > 0 } value)
            {
                rejected.Add($"${variable} is not set");
                continue;
            }

            if (RealPath(value) is not { } resolved)
            {
                rejected.Add($"${variable} ('{value}') does not resolve to a directory");
                continue;
            }

            // Its own chain first, so nothing is created under a location that can't be used.
            if (UntrustedDirectoryInChain(resolved) is { } problem)
            {
                rejected.Add($"${variable}: {problem}");
                continue;
            }

            var root = Path.Combine(resolved, relative);
            try
            {
                // One level at a time: Directory.CreateDirectory gives missing parents the umask's
                // mode, not the one asked for.
                var current = resolved;
                foreach (var part in relative.Split('/'))
                {
                    current = Path.Combine(current, part);
                    if (!Directory.Exists(current))
                        Directory.CreateDirectory(current, PrivateDirectoryMode);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                rejected.Add($"'{root}' could not be created: {ex.Message}");
                continue;
            }

            if (UntrustedDirectoryInChain(root) is { } rootProblem)
            {
                rejected.Add(rootProblem);
                continue;
            }

            return (root, null);
        }

        return (null, "Linux refuses key files below a group- or other-writable directory (such as /tmp), and no private folder was found for them: "
                      + string.Join("; ", rejected.Select(r => r.TrimEnd('.')).Distinct()) + ".");
    }

    [SupportedOSPlatform("linux")]
    private static string? RealPath(string path)
    {
        var resolved = realpath(path, IntPtr.Zero);
        if (resolved == IntPtr.Zero)
            return null;
        try
        {
            return Marshal.PtrToStringUTF8(resolved);
        }
        finally
        {
            free(resolved);
        }
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint GetLongPathNameW(string shortPath, [Out] char[] longPath, int bufferLength);

    [LibraryImport("libc.so.6")]
    private static partial uint geteuid();

    [LibraryImport("libc.so.6", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr realpath(string path, IntPtr resolvedPath);

    [LibraryImport("libc.so.6")]
    private static partial void free(IntPtr pointer);
}
