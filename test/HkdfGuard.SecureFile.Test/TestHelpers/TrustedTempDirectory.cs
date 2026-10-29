using System.Runtime.InteropServices;

namespace HkdfGuard.SecureFile.Test.TestHelpers;

/// <summary>
/// A fresh folder the trust checks accept once <see cref="Trust"/> trusts the current user: on
/// Windows one under the user's temp folder, named by its long path; on Linux and macOS one
/// beside the test assembly, readable and writable by its owner only - never under /tmp, which
/// is writable by everyone and so never trusted. Shared, by link, with every test project that
/// reads files through TrustedFile.
/// </summary>
internal sealed class TrustedTempDirectory : IDisposable
{
    private readonly WindowsTempDirectory? _windows;

    public TrustedTempDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            _windows = new WindowsTempDirectory();
            Path = _windows.Path;
            Trust = WindowsTempDirectory.TrustCurrentUser;
            return;
        }

        Path = System.IO.Path.Combine(AppContext.BaseDirectory, $"trusted-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Trust = new KeyFileTrust { UnixUserIds = [geteuid()], UnixGroupIds = [getegid()] };
    }

    public string Path { get; }

    /// <summary>Trusts the current user, whose files these are.</summary>
    public KeyFileTrust Trust { get; }

    public string Write(string name, byte[] contents)
    {
        var path = System.IO.Path.Combine(Path, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    public string Write(string name, string contents) => Write(name, System.Text.Encoding.UTF8.GetBytes(contents));

    // Tolerates a test having removed the folder itself.
    public void Dispose()
    {
        if (!Directory.Exists(Path))
            return;

        if (_windows is not null)
            _windows.Dispose();
        else
            Directory.Delete(Path, recursive: true);
    }

    [DllImport("libc")]
    private static extern uint geteuid();

    [DllImport("libc")]
    private static extern uint getegid();
}
