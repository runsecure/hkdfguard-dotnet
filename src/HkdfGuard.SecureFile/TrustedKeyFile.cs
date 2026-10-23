using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.SecureFile;

/// <summary>
/// Reads a key file only after its location passes the platform's checks (WindowsKeyFileChecks,
/// UnixKeyFileChecks): the managed equivalent of the native library's hkdfguard_open_file, for an
/// <see cref="IKeyWrapper.ReadKeyFileAsync"/> with no native library to read through - a network
/// KMS's key wrapper, say. The contents are then held to the same rules: 1 to
/// <see cref="WrappedKeyLimits.MaxBytes"/> bytes, never more than one byte past that read, and not
/// something that looks like an unwrapped key.
/// </summary>
public static class TrustedKeyFile
{
    /// <summary>The length of an unwrapped DEK; a file this size is probably a plaintext key.</summary>
    internal const int PlaintextKeyLength = 32;

    // A 32-byte key as text is at most 64 hex digits; allow surrounding whitespace.
    internal const int PlaintextTextScanLimit = 96;

    /// <summary>
    /// Reads the key file at <paramref name="path"/>, still wrapped, refusing it unless only the
    /// operating system's administrators and <paramref name="trust"/> could have written or
    /// replaced it, and refusing contents that aren't a wrapped key.
    /// </summary>
    /// <param name="path">The key file's path, absolute or relative to the working directory.</param>
    /// <param name="trust">Who besides administrators is trusted; <see cref="KeyFileTrust.AdministratorsOnly"/> for no one.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The file's contents.</returns>
    /// <exception cref="FileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read it, or its location isn't trusted.</exception>
    /// <exception cref="InvalidDataException">It is empty, too long, or holds what looks like an unwrapped key.</exception>
    /// <exception cref="IOException">It can't be read, or another process has it open for writing.</exception>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty, or <paramref name="trust"/> names a principal that can't be trusted.</exception>
    /// <exception cref="PlatformNotSupportedException">Not Windows, Linux or an Apple silicon Mac.</exception>
    [ExcludeFromCodeCoverage(Justification = "Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.")]
    public static ValueTask<byte[]> ReadAsync(string path, KeyFileTrust trust, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(trust);

        if (OperatingSystem.IsWindows())
            return ReadWindowsAsync(path, trust, cancellationToken);
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            return ReadUnixAsync(path, trust, cancellationToken);

        throw new PlatformNotSupportedException("Key files are read on Windows, Linux and macOS only.");
    }

    [SupportedOSPlatform("windows")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered WindowsKeyFileChecks policy to real files; exercised by the Windows-only real-file tests.")]
    private static async ValueTask<byte[]> ReadWindowsAsync(string path, KeyFileTrust trust, CancellationToken cancellationToken)
    {
        var trusted = WindowsKeyFileChecks.TrustedPrincipals(trust);
        var fullPath = Path.GetFullPath(path);
        WindowsKeyFileChecks.VerifyPathForm(fullPath,
            fullPath.StartsWith(@"\\", StringComparison.Ordinal) ? DriveType.Network : new DriveInfo(Path.GetPathRoot(fullPath)!).DriveType);

        // FileShare.Read: refused if another process has it open for writing, and no one can open
        // it for writing while it's read.
        await using var stream = Open(fullPath);
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

        return await ReadContentsAsync(stream, fullPath, cancellationToken).ConfigureAwait(false);
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [ExcludeFromCodeCoverage(Justification = "Wires the covered UnixKeyFileChecks policy to real files; exercised by the Unix-only real-file tests.")]
    private static async ValueTask<byte[]> ReadUnixAsync(string path, KeyFileTrust trust, CancellationToken cancellationToken)
    {
        // The working directory is already a resolved path; ResolveTrusted handles ".." itself.
        var absolute = path.StartsWith('/') ? path : Path.Join(Directory.GetCurrentDirectory(), path);
        var resolved = UnixKeyFileChecks.ResolveTrusted(absolute, trust, UnixNative.GetStatusOrNull, UnixNative.ReadLink);

        await using var stream = Open(resolved);
        return await ReadContentsAsync(stream, path, cancellationToken).ConfigureAwait(false);
    }

    private static FileStream Open(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.Read,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
    });

    /// <summary>
    /// Reads at most one byte past <see cref="WrappedKeyLimits.MaxBytes"/> from <paramref name="stream"/>
    /// - so a wrong path (a log, a device) can't make startup allocate an unbounded buffer - and
    /// refuses an empty file, one over the limit, and one that looks like an unwrapped key. Whatever
    /// is refused is zeroed.
    /// </summary>
    /// <exception cref="InvalidDataException">The contents are refused.</exception>
    internal static async ValueTask<byte[]> ReadContentsAsync(Stream stream, string path, CancellationToken cancellationToken)
    {
        var buffer = new byte[WrappedKeyLimits.MaxBytes + 1];
        try
        {
            var total = 0;
            int read;
            while (total < buffer.Length
                   && (read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false)) > 0)
                total += read;

            if (total == 0)
                throw new InvalidDataException($"Key file '{path}' is empty.");
            if (total > WrappedKeyLimits.MaxBytes)
                throw new InvalidDataException(
                    $"Key file '{path}' is larger than {WrappedKeyLimits.MaxBytes} bytes (WrappedKeyLimits.MaxBytes); a wrapped key never is.");
            if (LooksLikePlaintextKey(buffer.AsSpan(0, total)))
                throw new InvalidDataException(
                    $"Key file '{path}' holds what looks like an unwrapped 32-byte key, not a wrapped one. Treat that key as exposed: replace it, and write key files with the key wrapper.");

            return buffer[..total];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// The native library's test for a plaintext key written to disk: exactly 32 bytes, or a 32-byte
    /// key as 64 hex digits or as base64 (standard or URL-safe, padded or not), with any surrounding
    /// whitespace.
    /// </summary>
    internal static bool LooksLikePlaintextKey(ReadOnlySpan<byte> contents)
    {
        if (contents.Length == PlaintextKeyLength)
            return true;
        if (contents.Length > PlaintextTextScanLimit)
            return false;

        var text = contents.Trim(" \t\r\n\v\f"u8);
        return IsHexKey(text) || IsBase64Key(text);
    }

    private static bool IsHexKey(ReadOnlySpan<byte> text)
    {
        if (text.Length != PlaintextKeyLength * 2)
            return false;
        foreach (var c in text)
        {
            if (!char.IsAsciiHexDigit((char)c))
                return false;
        }

        return true;
    }

    private static bool IsBase64Key(ReadOnlySpan<byte> text)
    {
        // 32 bytes: 43 characters, then one '=' when padded.
        var unpadded = text.Length == 44 && text[43] == '=' ? text[..43] : text;
        if (unpadded.Length != 43)
            return false;

        var urlSafe = false;
        var standard = false;
        foreach (var c in unpadded)
        {
            if (char.IsAsciiLetterOrDigit((char)c))
                continue;
            if (c is (byte)'+' or (byte)'/')
                standard = true;
            else if (c is (byte)'-' or (byte)'_')
                urlSafe = true;
            else
                return false;
        }

        return !(urlSafe && standard);
    }
}
