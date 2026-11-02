using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using HkdfGuard.Abstractions;

namespace HkdfGuard.SecureFile;

/// <summary>
/// Reads a file only after its location passes the platform's checks (WindowsKeyFileChecks,
/// UnixKeyFileChecks) - the same symbolic-link, ownership and permission checks
/// <see cref="TrustedKeyFile"/> applies - but with none of a key file's rules about its contents:
/// for secret files, certificates and anything else that must come from where only the operating
/// system's administrators and <see cref="KeyFileTrust"/> principals could have put it. What the
/// contents must look like is the caller's to check.
/// <para>
/// The caller says how large the file may be. At most one byte past that is read, whatever the
/// file reports as its length, so a wrong path (a log, a device) can't make it read without end;
/// the buffer is allocated at that size up front, so keep it close to the largest file expected.
/// </para>
/// </summary>
public static class TrustedFile
{
    /// <summary>
    /// Reads the file at <paramref name="path"/>, refusing it unless only the operating system's
    /// administrators and <paramref name="trust"/> could have written or replaced it, or if it is
    /// longer than <paramref name="maxBytes"/>. For contents that are not themselves secret - a
    /// value encrypted elsewhere, a public certificate; use the overload that takes a parser for
    /// anything that is.
    /// </summary>
    /// <param name="path">The file's path, absolute or relative to the working directory.</param>
    /// <param name="trust">Who besides administrators is trusted; <see cref="KeyFileTrust.AdministratorsOnly"/> for no one.</param>
    /// <param name="maxBytes">The longest file accepted.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The file's contents, which may be empty.</returns>
    /// <exception cref="FileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read it, or its location isn't trusted.</exception>
    /// <exception cref="InvalidDataException">It is longer than <paramref name="maxBytes"/>.</exception>
    /// <exception cref="IOException">It can't be read, or another process has it open for writing.</exception>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty, or <paramref name="trust"/> names a principal that can't be trusted.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBytes"/> isn't positive, or is too large for one array.</exception>
    /// <exception cref="PlatformNotSupportedException">Not Windows, Linux or an Apple silicon Mac.</exception>
    public static async ValueTask<byte[]> ReadAsync(string path, KeyFileTrust trust, int maxBytes, CancellationToken cancellationToken = default)
    {
        ValidateArguments(path, trust, maxBytes);
        await using var stream = OpenTrusted(path, trust);
        return await ReadContentsAsync(stream, path, maxBytes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the file at <paramref name="path"/> as <see cref="ReadAsync(string, KeyFileTrust, int, CancellationToken)"/>
    /// does, into pinned memory, and hands the contents to <paramref name="parse"/> - for contents
    /// that are themselves secret, such as a PFX or a PEM private key. The buffer is zeroed once
    /// parse returns or throws, so parse must not keep the span, and should zero any copy it makes.
    /// </summary>
    /// <param name="path">The file's path, absolute or relative to the working directory.</param>
    /// <param name="trust">Who besides administrators is trusted; <see cref="KeyFileTrust.AdministratorsOnly"/> for no one.</param>
    /// <param name="maxBytes">The longest file accepted.</param>
    /// <param name="parse">Turns the contents, which may be empty, into the result.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>What <paramref name="parse"/> returned.</returns>
    /// <exception cref="FileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read it, or its location isn't trusted.</exception>
    /// <exception cref="InvalidDataException">It is longer than <paramref name="maxBytes"/>.</exception>
    /// <exception cref="IOException">It can't be read, or another process has it open for writing.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="parse"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty, or <paramref name="trust"/> names a principal that can't be trusted.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxBytes"/> isn't positive, or is too large for one array.</exception>
    /// <exception cref="PlatformNotSupportedException">Not Windows, Linux or an Apple silicon Mac.</exception>
    public static async ValueTask<T> ReadAsync<T>(string path, KeyFileTrust trust, int maxBytes, Func<ReadOnlySpan<byte>, T> parse,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(path, trust, maxBytes);
        ArgumentNullException.ThrowIfNull(parse);
        await using var stream = OpenTrusted(path, trust);
        return await ReadContentsAsync(stream, path, maxBytes, parse, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Opens <paramref name="path"/> for reading once the platform's checks have passed, refusing
    /// it if another process has it open for writing; while it's open, no one can open it for writing.
    /// </summary>
    /// <exception cref="FileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read it, or its location isn't trusted.</exception>
    /// <exception cref="IOException">Another process has it open for writing.</exception>
    /// <exception cref="ArgumentException"><paramref name="trust"/> names a principal that can't be trusted.</exception>
    /// <exception cref="PlatformNotSupportedException">Not Windows, Linux or an Apple silicon Mac.</exception>
    [ExcludeFromCodeCoverage(Justification = "Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.")]
    internal static FileStream OpenTrusted(string path, KeyFileTrust trust)
    {
        if (OperatingSystem.IsWindows())
            return OpenWindows(path, trust);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            return OpenUnix(path, trust);

        throw new PlatformNotSupportedException("Trusted files are read on Windows, Linux and macOS only.");
    }

    /// <summary>
    /// Reads at most one byte past <paramref name="maxBytes"/> from <paramref name="stream"/>,
    /// refusing a longer file, and returns what was read. The read buffer is zeroed.
    /// </summary>
    /// <exception cref="InvalidDataException">The contents are longer than maxBytes.</exception>
    internal static async ValueTask<byte[]> ReadContentsAsync(Stream stream, string path, int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[maxBytes + 1];
        try
        {
            var total = await ReadBoundedAsync(stream, buffer, path, cancellationToken).ConfigureAwait(false);
            return buffer[..total];
        }
        finally
        {
            ArrayUtility.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Reads as <see cref="ReadContentsAsync(Stream, string, int, CancellationToken)"/> does, into
    /// a pinned buffer, and returns what <paramref name="parse"/> makes of it; the buffer is zeroed
    /// whether parse returns or throws.
    /// </summary>
    /// <exception cref="InvalidDataException">The contents are longer than maxBytes.</exception>
    internal static async ValueTask<T> ReadContentsAsync<T>(Stream stream, string path, int maxBytes, Func<ReadOnlySpan<byte>, T> parse,
        CancellationToken cancellationToken)
    {
        // Pinned, so the GC never leaves a copy of what may be a private key behind.
        var buffer = ArrayUtility.AllocatePinned<byte>(maxBytes + 1);
        try
        {
            var total = await ReadBoundedAsync(stream, buffer, path, cancellationToken).ConfigureAwait(false);
            return parse(buffer.AsSpan(0, total));
        }
        finally
        {
            ArrayUtility.ZeroMemory(buffer);
        }
    }

    private static void ValidateArguments(string path, KeyFileTrust trust, int maxBytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(maxBytes, Array.MaxLength);
    }

    // Fills buffer as far as the stream goes; buffer is one byte longer than the longest file
    // accepted, so filling it means the file is too long.
    private static async ValueTask<int> ReadBoundedAsync(Stream stream, Memory<byte> buffer, string path, CancellationToken cancellationToken)
    {
        var total = 0;
        int read;
        while (total < buffer.Length
               && (read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false)) > 0)
            total += read;

        if (total == buffer.Length)
            throw new InvalidDataException($"'{path}' is larger than {buffer.Length - 1} bytes, the most it may be.");
        return total;
    }

    [SupportedOSPlatform("windows")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered WindowsKeyFileChecks policy to real files; exercised by the Windows-only real-file tests.")]
    private static FileStream OpenWindows(string path, KeyFileTrust trust)
    {
        var trusted = WindowsKeyFileChecks.TrustedPrincipals(trust);
        var fullPath = Path.GetFullPath(path);
        WindowsKeyFileChecks.VerifyPathForm(fullPath,
            fullPath.StartsWith(@"\\", StringComparison.Ordinal) ? DriveType.Network : new DriveInfo(Path.GetPathRoot(fullPath)!).DriveType);

        var stream = Open(fullPath);
        try
        {
            WindowsKeyFileChecks.VerifyFinalPath(fullPath, WindowsNative.GetFinalPath(stream.SafeFileHandle));

            // The file through its own handle; the folders by path, which the final-path check ties to
            // the folders it was opened through, and which no untrusted principal can then change.
            WindowsKeyFileChecks.VerifyTrustedOnly(stream.GetAccessControl(), fullPath, fullPath, WindowsKeyFileChecks.GuardedRights, trusted);
            for (var folder = new FileInfo(fullPath).Directory; folder is not null; folder = folder.Parent)
            {
                var security = folder.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                if (folder.Parent is null)
                {
                    WindowsKeyFileChecks.VerifyTrustedOnly(security, fullPath, folder.FullName, WindowsKeyFileChecks.GuardedRootRights, trusted);
                    break;
                }

                WindowsKeyFileChecks.VerifyNotReparsePoint(folder.Attributes, fullPath, folder.FullName);
                WindowsKeyFileChecks.VerifyTrustedOnly(security, fullPath, folder.FullName, WindowsKeyFileChecks.GuardedRights, trusted);
            }

            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered UnixKeyFileChecks policy to real files; exercised by the Unix-only real-file tests.")]
    private static FileStream OpenUnix(string path, KeyFileTrust trust)
    {
        // The working directory is already a resolved path; ResolveTrusted handles ".." itself.
        var absolute = path.StartsWith('/') ? path : Path.Join(Directory.GetCurrentDirectory(), path);
        return Open(UnixKeyFileChecks.ResolveTrusted(absolute, trust, UnixNative.GetStatusOrNull, UnixNative.ReadLink));
    }

    // FileShare.Read: refused if another process has it open for writing, and no one can open it
    // for writing while it's read.
    private static FileStream Open(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.Read,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
    });
}
