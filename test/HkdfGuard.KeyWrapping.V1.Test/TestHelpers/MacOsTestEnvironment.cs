using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

/// <summary>
/// The macOS install the native tests run against: the library MacOsNativeLibraryLoader would
/// choose, and the hkdfguard provisioning tool installed beside it.
/// </summary>
[SupportedOSPlatform("macos")]
internal static class MacOsTestEnvironment
{
    public const string ProvisioningToolName = "hkdfguard";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(60);

    public static string HomeDirectory
        => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);

    /// <summary>
    /// The install the loader would choose, or null when there is none. A location that can't be
    /// examined is reported as installed, so the tests run and report that failure.
    /// </summary>
    public static (string Path, bool IsSystem)? InstalledLibrary
    {
        get
        {
            try
            {
                return MacOsNativeLibraryLoader.ChoosePath(MacOsNative.Probe, HomeDirectory);
            }
            catch (DllNotFoundException)
            {
                return null;
            }
            catch (SecurityException)
            {
                return (MacOsNativeLibraryLoader.SystemPath, true);
            }
        }
    }

    /// <summary>The provisioning tool installed beside the chosen library, or null if there is none.</summary>
    public static string? ProvisioningTool
        => InstalledLibrary is { } installed
           && Path.Combine(Path.GetDirectoryName(installed.Path)!, ProvisioningToolName) is var tool
           && File.Exists(tool)
            ? tool
            : null;

    /// <summary>Runs <paramref name="tool"/> with <paramref name="arguments"/>: its exit code and its combined output.</summary>
    public static (int ExitCode, string Output) Run(string tool, params string[] arguments)
    {
        var start = new ProcessStartInfo(tool)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(ToolTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{tool} {string.Join(' ', arguments)} did not exit within {ToolTimeout}.");
        }

        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
