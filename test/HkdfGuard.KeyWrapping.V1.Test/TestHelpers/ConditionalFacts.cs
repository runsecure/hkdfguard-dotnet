using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.Abstractions;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

/// <summary>A test that only means anything on Windows; reported as skipped elsewhere.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows only.";
    }
}

/// <summary>The theory form of <see cref="WindowsFactAttribute"/>.</summary>
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows only.";
    }
}

/// <summary>
/// A test that needs the real Windows native KMS library installed at its one supported location
/// (%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll); reported as skipped when it isn't.
/// </summary>
public sealed class InstalledWindowsLibraryFactAttribute : FactAttribute
{
    public InstalledWindowsLibraryFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows only.";
        else if (!File.Exists(WindowsNativeLibraryLoader.InstalledPath))
            Skip = $"The native KMS library is not installed at {WindowsNativeLibraryLoader.InstalledPath}.";
    }
}

/// <summary>The theory form of <see cref="InstalledWindowsLibraryFactAttribute"/>.</summary>
public sealed class InstalledWindowsLibraryTheoryAttribute : TheoryAttribute
{
    public InstalledWindowsLibraryTheoryAttribute()
    {
        if (!OperatingSystem.IsWindows())
            Skip = "Windows only.";
        else if (!File.Exists(WindowsNativeLibraryLoader.InstalledPath))
            Skip = $"The native KMS library is not installed at {WindowsNativeLibraryLoader.InstalledPath}.";
    }
}

/// <summary>
/// A test that makes real calls into this platform's native KMS library. Every platform's library
/// refuses to create a KEK during wrap/unwrap - one must be provisioned beforehand - so these tests
/// run only against a provisioned service (see <see cref="NativeTestEnvironment.ServiceName"/>) and
/// are reported as skipped otherwise. Once a service is chosen, a missing or failing library is a
/// test failure, never a silent pass. Tests get the service from
/// <see cref="NativeTestEnvironment.ProvisionedService"/>.
/// </summary>
public sealed class NativeIntegrationFactAttribute : FactAttribute
{
    /// <summary>
    /// Needs a folder the native library trusts for key files
    /// (<see cref="TestDirectories.CreateKeyFileDirectory"/>); on Linux there may be none.
    /// </summary>
    public bool NeedsKeyFileDirectory { get; set; }

    public override string? Skip
    {
        get => base.Skip
               ?? (NativeTestEnvironment.ServiceName is null ? NativeTestEnvironment.SkipReason
                   : NeedsKeyFileDirectory ? TestDirectories.KeyFileDirectorySkipReason
                   : null);
        set => base.Skip = value;
    }
}

public static class NativeTestEnvironment
{
    /// <summary>
    /// Names a service already provisioned on this machine; its KEK is used, never created or
    /// deleted. Always wins over <see cref="DefaultServiceName"/>, and is never skipped:
    /// setting it means the native tests must run.
    /// </summary>
    public const string ServiceVariable = "HKDFGUARD_TEST_SERVICE";

    /// <summary>
    /// The test KEK every platform's tests use, in every HkdfGuard port: on Windows
    /// scripts/provision-windows-test-key.ps1 provisions it, on Linux
    /// scripts/provision-linux-test-key.sh, on macOS hkdfguard provision (or
    /// hkdfguard-go's scripts/provision-macos-test-key.sh). Used when <see cref="ServiceVariable"/>
    /// is unset and, on Windows and macOS, the installed library or provisioning tool reports it
    /// exists.
    /// </summary>
    public const string DefaultServiceName = "com.hkdfguard.integration.test.221";

    /// <summary>
    /// How long the first native call under the test service may take
    /// (<see cref="ProvisionedService"/>) before the run fails rather than hangs.
    /// </summary>
    public static readonly TimeSpan NativeCallTimeout = TimeSpan.FromSeconds(60);

    private static readonly Lazy<(string? Service, string SkipReason)> Resolved = new(Resolve);

    private static readonly Lazy<string?> NativeAccessFailure = new(ProbeNativeAccess);

    /// <summary>
    /// The service the native tests run against: <see cref="ServiceVariable"/> if set; otherwise,
    /// on Windows and macOS, <see cref="DefaultServiceName"/> - unless the installed library (or
    /// provisioning tool) reports that its KEK isn't provisioned or this account may not use it,
    /// when this is null and the tests are skipped with <see cref="SkipReason"/>. Any other answer
    /// runs the tests, so a real failure is reported rather than hidden. Linux has no way to ask
    /// without the KEK's provider, so there it is only ever <see cref="ServiceVariable"/>.
    /// </summary>
    public static string? ServiceName => Resolved.Value.Service;

    public static string SkipReason => Resolved.Value.SkipReason;

    /// <summary>
    /// <see cref="ServiceName"/>, for a test gated on it, once the first native call under it has
    /// returned. On macOS that first call can wait forever on a keychain dialog nobody answers: the
    /// KEK's keychain item names the binary that created it (the provisioning tool), so the first
    /// call from any other binary - every freshly built test host - is answered with a keychain
    /// dialog in a logged-in session. It is made once per process with
    /// <see cref="NativeCallTimeout"/>, and every test that asks for the service fails, saying so,
    /// if it hasn't returned by then. What the call answers is left to each test.
    /// </summary>
    public static string ProvisionedService
    {
        get
        {
            var service = ServiceName ?? throw new InvalidOperationException($"No provisioned test service: {SkipReason}");
            if (OperatingSystem.IsMacOS() && NativeAccessFailure.Value is { } failure)
                Assert.Fail(failure);
            return service;
        }
    }

    /// <summary>
    /// Runs <paramref name="call"/> - a native call that may show a keychain or Secure Enclave
    /// authorization dialog on macOS - and fails the test, naming <paramref name="service"/>, if it
    /// hasn't returned within <paramref name="timeout"/> (default <see cref="NativeCallTimeout"/>)
    /// rather than hang it. The call keeps running on a background thread that doesn't hold the
    /// process open.
    /// </summary>
    public static T WithinNativeCallTimeout<T>(string service, Func<T> call, TimeSpan? timeout = null)
    {
        if (AwaitNativeCall(service, call, timeout ?? NativeCallTimeout, out var result) is { } failure)
            Assert.Fail(failure);
        return result!;
    }

    /// <summary>
    /// Runs <paramref name="call"/> on a background thread and waits up to
    /// <paramref name="timeout"/>: null with its result (or rethrowing what it threw) if it
    /// returned, otherwise the message a test fails with.
    /// </summary>
    internal static string? AwaitNativeCall<T>(string service, Func<T> call, TimeSpan timeout, out T? result)
    {
        T? value = default;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? thrown = null;
        var thread = new Thread(() =>
        {
            try
            {
                value = call();
            }
            catch (Exception ex)
            {
                thrown = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex);
            }
        })
        {
            IsBackground = true,
            Name = "HkdfGuard native call",
        };
        thread.Start();

        if (!thread.Join(timeout))
        {
            result = default;
            return $"A native call under service '{service}' has not returned after {timeout.TotalSeconds:0.###} seconds. "
                   + "On macOS the KEK's keychain item is asking for access in a dialog nobody has answered: click \"Always Allow\" "
                   + "(every freshly built test host asks once). In a session with no UI the library reports "
                   + "KEK_ACCESS_DENIED (-18) instead; run the tests from a logged-in session.";
        }

        thrown?.Throw();
        result = value;
        return null;
    }

    private static string? ProbeNativeAccess()
    {
        var service = ServiceName!;
        return AwaitNativeCall(service, () =>
        {
            try
            {
                return NativeHost.Library.GenerateAndWrapDek(service, new byte[WrappedKeyLimits.MaxBytes], out _);
            }
            catch (Exception)
            {
                return int.MinValue; // what it answers is each test's business; only a hang is ours
            }
        }, NativeCallTimeout, out _);
    }

    private static (string? Service, string SkipReason) Resolve()
    {
        if (Read(ServiceVariable) is { } explicitName)
            return (explicitName, string.Empty);

        if (OperatingSystem.IsMacOS())
            return ResolveMacOs();

        if (!OperatingSystem.IsWindows())
            return (null, $"Set {ServiceVariable} to a service provisioned with hkdfguard to run native integration tests. On a Linux TPM host, sudo scripts/provision-linux-test-key.sh provisions {DefaultServiceName}.");

        if (!File.Exists(Interop.WindowsNativeLibraryLoader.InstalledPath))
            return (null, $"The native KMS library is not installed at {Interop.WindowsNativeLibraryLoader.InstalledPath}.");

        int status;
        bool exists;
        try
        {
            (status, exists) = WindowsKekProbe.Query(DefaultServiceName);
        }
        catch (Exception)
        {
            // Installed, but it couldn't even be asked (it failed verification, say): run the
            // tests so that failure is reported.
            return (DefaultServiceName, string.Empty);
        }

        return status switch
        {
            0 when exists => (DefaultServiceName, string.Empty),
            0 or Interop.AbstractHkdfGuardKmsLibrary.ErrKekNotFound =>
                (null, $"The test KEK '{DefaultServiceName}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set {ServiceVariable} to a provisioned service."),
            Interop.AbstractHkdfGuardKmsLibrary.ErrKekAccessDenied =>
                (null, $"The test KEK '{DefaultServiceName}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated."),
            _ => (DefaultServiceName, string.Empty),
        };
    }

    /// <summary>
    /// The macOS default: <see cref="DefaultServiceName"/>, as the installed
    /// hkdfguard (beside the library the loader would choose) reports it. The tool
    /// created the KEK, so it is on the keychain item's access list and never prompts; asking the
    /// library from this process would. Skipped only when the library isn't installed or the tool
    /// reports the KEK absent; any other answer runs the tests, so a real failure is reported.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("macos")]
    internal static (string? Service, string SkipReason) ResolveMacOs()
    {
        if (MacOsTestEnvironment.InstalledLibrary is null)
            return (null, $"The native KMS library is not installed at {Interop.MacOsNativeLibraryLoader.SystemPath} or {Interop.MacOsNativeLibraryLoader.UserPath(MacOsTestEnvironment.HomeDirectory)}.");

        if (MacOsTestEnvironment.ProvisioningTool is not { } tool)
            return (DefaultServiceName, string.Empty);

        string output;
        try
        {
            (var exitCode, output) = MacOsTestEnvironment.Run(tool, "status", "--service-name", DefaultServiceName);
            if (exitCode != 0)
                return (DefaultServiceName, string.Empty);
        }
        catch (Exception)
        {
            return (DefaultServiceName, string.Empty);
        }

        if (output.Contains("kek: absent", StringComparison.Ordinal))
            return (null, $"The test KEK '{DefaultServiceName}' is not provisioned. Run {MacOsTestEnvironment.ProvisioningToolName} provision --service-name {DefaultServiceName}, or set {ServiceVariable} to a provisioned service.");

        return (DefaultServiceName, string.Empty);
    }

    /// <summary>
    /// Optional second provisioned service, for the cross-service isolation test. When unset, that
    /// test unwraps under <see cref="UnprovisionedServiceName"/> instead, which must also fail.
    /// </summary>
    public const string OtherServiceVariable = "HKDFGUARD_TEST_SERVICE_OTHER";

    /// <summary>A valid service name (ASCII letters, digits, '.') that is never provisioned.</summary>
    public const string UnprovisionedServiceName = "hkdfguard.integrationtest.unprovisioned";

    public static string OtherServiceName => Read(OtherServiceVariable) ?? UnprovisionedServiceName;

    private static string? Read(string variable)
        => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value ? value : null;
}

/// <summary>
/// A test that needs the real Linux native KMS library installed by its package (any of
/// LinuxNativeLibraryLoader's candidate locations); reported as skipped when it isn't.
/// </summary>
public sealed class InstalledLinuxLibraryFactAttribute : FactAttribute
{
    public InstalledLinuxLibraryFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Linux only.";
        else if (InstalledPath is null)
            Skip = "The libhkdfguard1 package is not installed.";
    }

    /// <summary>Where the package installed the library, or null if it isn't installed.</summary>
    public static string? InstalledPath
    {
        get
        {
            try
            {
                return LinuxNativeLibraryLoader.CandidatePaths(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture).FirstOrDefault(File.Exists);
            }
            catch (PlatformNotSupportedException)
            {
                return null; // no package for this architecture
            }
        }
    }
}

/// <summary>
/// A test that only means anything on macOS; reported as skipped elsewhere, and when
/// <see cref="NeedsFile"/> names a file that isn't there.
/// </summary>
public sealed class MacOsFactAttribute : FactAttribute
{
    /// <summary>A file the test needs, such as an installed tool.</summary>
    public string? NeedsFile { get; set; }

    public override string? Skip
    {
        get => base.Skip
               ?? (!OperatingSystem.IsMacOS() ? "macOS only."
                   : NeedsFile is { } file && !File.Exists(file) ? $"{file} is not installed."
                   : null);
        set => base.Skip = value;
    }
}

/// <summary>
/// A test that needs the real macOS native KMS library installed at one of its two supported
/// locations (MacOsNativeLibraryLoader.SystemPath, or ~/.hkdfguard/v1); reported as skipped when
/// it isn't. <see cref="NeedsProvisioningTool"/> also needs hkdfguard beside it.
/// </summary>
public sealed class InstalledMacOsLibraryFactAttribute : FactAttribute
{
    public bool NeedsProvisioningTool { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? Reason(NeedsProvisioningTool);
        set => base.Skip = value;
    }

    internal static string? Reason(bool needsProvisioningTool = false)
    {
        if (!OperatingSystem.IsMacOS())
            return "macOS only.";
        if (MacOsTestEnvironment.InstalledLibrary is null)
            return $"The native KMS library is not installed at {MacOsNativeLibraryLoader.SystemPath} or {MacOsNativeLibraryLoader.UserPath(MacOsTestEnvironment.HomeDirectory)}.";
        if (needsProvisioningTool && MacOsTestEnvironment.ProvisioningTool is null)
            return $"{MacOsTestEnvironment.ProvisioningToolName} is not installed beside the native KMS library.";
        return null;
    }
}

/// <summary>
/// A test that needs this platform's real native KMS library installed (Windows, Linux or macOS),
/// but no provisioned service; reported as skipped when it isn't installed.
/// </summary>
public sealed class InstalledNativeLibraryFactAttribute : FactAttribute
{
    public InstalledNativeLibraryFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            if (!File.Exists(WindowsNativeLibraryLoader.InstalledPath))
                Skip = $"The native KMS library is not installed at {WindowsNativeLibraryLoader.InstalledPath}.";
        }
        else if (OperatingSystem.IsLinux())
        {
            if (InstalledLinuxLibraryFactAttribute.InstalledPath is null)
                Skip = "The libhkdfguard1 package is not installed.";
        }
        else if (OperatingSystem.IsMacOS())
        {
            Skip = InstalledMacOsLibraryFactAttribute.Reason();
        }
        else
        {
            Skip = "No native KMS library exists for this platform.";
        }
    }

    /// <summary>Needs a folder the native library trusts for key files (see <see cref="NativeIntegrationFactAttribute.NeedsKeyFileDirectory"/>).</summary>
    public bool NeedsKeyFileDirectory { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? (NeedsKeyFileDirectory ? TestDirectories.KeyFileDirectorySkipReason : null);
        set => base.Skip = value;
    }
}

/// <summary>
/// A Linux test of what happens without the libhkdfguard1 package; reported as skipped elsewhere,
/// and where the package is installed (or none is built for this architecture).
/// </summary>
public sealed class UninstalledLinuxLibraryFactAttribute : FactAttribute
{
    public UninstalledLinuxLibraryFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
        {
            Skip = "Linux only.";
            return;
        }

        try
        {
            if (LinuxNativeLibraryLoader.CandidatePaths(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture).Any(File.Exists))
                Skip = "The libhkdfguard1 package is installed.";
        }
        catch (PlatformNotSupportedException)
        {
            Skip = "No libhkdfguard1 package is built for this architecture.";
        }
    }
}

/// <summary>A test that only means anything on Linux; reported as skipped elsewhere.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    /// <summary>Needs a folder the native library trusts for key files (see <see cref="TestDirectories.CreateKeyFileDirectory"/>).</summary>
    public bool NeedsKeyFileDirectory { get; set; }

    public override string? Skip
    {
        get => base.Skip
               ?? (!OperatingSystem.IsLinux() ? "Linux only."
                   : NeedsKeyFileDirectory ? TestDirectories.KeyFileDirectorySkipReason
                   : null);
        set => base.Skip = value;
    }
}

/// <summary>
/// A real call into the Linux native library against the provisioned test service (see
/// <see cref="NativeTestEnvironment"/>). Skipped off Linux, without the package, or without a
/// provisioned service; the named properties add requirements some tests need.
/// </summary>
public sealed class LinuxNativeIntegrationFactAttribute : FactAttribute
{
    public const string PolicyPath = "/etc/hkdfguard/policy.toml";
    public const string Cli = "/usr/bin/hkdfguard";

    /// <summary>Needs <see cref="NativeTestEnvironment.OtherServiceVariable"/>: a second provisioned service, with its own KEK.</summary>
    public bool NeedsOtherService { get; set; }

    /// <summary>Needs the policy's provisioning allowlist (tpm.require_pinned_names), so an unlisted service has no KEK.</summary>
    public bool NeedsPinnedNamesAllowlist { get; set; }

    /// <summary>Needs the hkdfguard package's hkdfguard.</summary>
    public bool NeedsCli { get; set; }

    /// <summary>Needs a folder the native library trusts for key files (see <see cref="TestDirectories.CreateKeyFileDirectory"/>).</summary>
    public bool NeedsKeyFileDirectory { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? Reason(NeedsOtherService, NeedsPinnedNamesAllowlist, NeedsCli, NeedsKeyFileDirectory);
        set => base.Skip = value;
    }

    internal static string? Reason(bool needsOtherService = false, bool needsPinnedNamesAllowlist = false, bool needsCli = false, bool needsKeyFileDirectory = false)
    {
        if (!OperatingSystem.IsLinux())
            return "Linux only.";
        if (InstalledLinuxLibraryFactAttribute.InstalledPath is null)
            return "The libhkdfguard1 package is not installed.";
        if (NativeTestEnvironment.ServiceName is null)
            return NativeTestEnvironment.SkipReason;
        if (needsOtherService && Environment.GetEnvironmentVariable(NativeTestEnvironment.OtherServiceVariable) is not { Length: > 0 })
            return $"Set {NativeTestEnvironment.OtherServiceVariable} to a second provisioned service.";
        if (needsPinnedNamesAllowlist && !PolicyRequiresPinnedNames())
            return $"{PolicyPath} does not set tpm.require_pinned_names = true (scripts/provision-linux-test-key.sh does).";
        if (needsCli && !File.Exists(Cli))
            return $"{Cli} is not installed (the hkdfguard package).";
        if (needsKeyFileDirectory && TestDirectories.KeyFileDirectorySkipReason is { } noDirectory)
            return noDirectory;
        return null;
    }

    private static bool PolicyRequiresPinnedNames()
    {
        try
        {
            return File.ReadLines(PolicyPath).Any(l => l.Replace(" ", string.Empty, StringComparison.Ordinal) == "require_pinned_names=true");
        }
        catch (IOException)
        {
            return false;
        }
    }
}

/// <summary>The theory form of <see cref="LinuxNativeIntegrationFactAttribute"/>.</summary>
public sealed class LinuxNativeIntegrationTheoryAttribute : TheoryAttribute
{
    /// <summary>Needs a trusted folder for key files (see TestDirectories.KeyFileDirectorySkipReason).</summary>
    public bool NeedsKeyFileDirectory { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? LinuxNativeIntegrationFactAttribute.Reason(needsKeyFileDirectory: NeedsKeyFileDirectory);
        set => base.Skip = value;
    }
}
