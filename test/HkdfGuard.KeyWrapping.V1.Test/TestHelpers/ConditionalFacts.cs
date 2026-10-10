using HkdfGuard.KeyWrapping.V1.Interop;

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
/// (%ProgramFiles%\HkdfGuard\v1\HkdfGuardV1.dll); reported as skipped when it isn't.
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

/// <summary>
/// A test that makes real calls into this platform's native KMS library. Every platform's library
/// refuses to create a KEK during wrap/unwrap - one must be provisioned beforehand - so these tests
/// run only against a provisioned service (see <see cref="NativeTestEnvironment.ServiceName"/>) and
/// are reported as skipped otherwise. Once a service is chosen, a missing or failing library is a
/// test failure, never a silent pass.
/// </summary>
public sealed class NativeIntegrationFactAttribute : FactAttribute
{
    public NativeIntegrationFactAttribute()
    {
        if (NativeTestEnvironment.ServiceName is null)
            Skip = NativeTestEnvironment.SkipReason;
    }
}

public static class NativeTestEnvironment
{
    /// <summary>
    /// Names a service already provisioned on this machine; its KEK is used, never created or
    /// deleted. Always wins over <see cref="DefaultWindowsServiceName"/>, and is never skipped:
    /// setting it means the native tests must run.
    /// </summary>
    public const string ServiceVariable = "HKDFGUARD_TEST_SERVICE";

    /// <summary>
    /// The Windows test KEK that scripts/provision-windows-test-key.ps1 provisions. Used when
    /// <see cref="ServiceVariable"/> is unset and the installed library reports it exists.
    /// </summary>
    public const string DefaultWindowsServiceName = "com.hkdfguard.native.windows.test";

    private static readonly Lazy<(string? Service, string SkipReason)> Resolved = new(Resolve);

    /// <summary>
    /// The service the native tests run against: <see cref="ServiceVariable"/> if set; otherwise,
    /// on Windows, <see cref="DefaultWindowsServiceName"/> - unless the installed library reports
    /// that its KEK isn't provisioned or this account may not use it, when this is null and the
    /// tests are skipped with <see cref="SkipReason"/>. Any other answer runs the tests, so a real
    /// failure is reported rather than hidden.
    /// </summary>
    public static string? ServiceName => Resolved.Value.Service;

    public static string SkipReason => Resolved.Value.SkipReason;

    private static (string? Service, string SkipReason) Resolve()
    {
        if (Read(ServiceVariable) is { } explicitName)
            return (explicitName, string.Empty);

        if (!OperatingSystem.IsWindows())
            return (null, $"Set {ServiceVariable} to a service provisioned with hkdfguard-v1-initialize to run native integration tests. On a Linux TPM host, sudo scripts/provision-linux-test-key.sh provisions com.hkdfguard.native.linux.test.");

        if (!File.Exists(Interop.WindowsNativeLibraryLoader.InstalledPath))
            return (null, $"The native KMS library is not installed at {Interop.WindowsNativeLibraryLoader.InstalledPath}.");

        int status;
        bool exists;
        try
        {
            (status, exists) = WindowsKekProbe.Query(DefaultWindowsServiceName);
        }
        catch (Exception)
        {
            // Installed, but it couldn't even be asked (it failed verification, say): run the
            // tests so that failure is reported.
            return (DefaultWindowsServiceName, string.Empty);
        }

        return status switch
        {
            0 when exists => (DefaultWindowsServiceName, string.Empty),
            0 or Interop.WindowsHkdfGuardKmsLibrary.ErrKekNotFound =>
                (null, $"The test KEK '{DefaultWindowsServiceName}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set {ServiceVariable} to a provisioned service."),
            Interop.WindowsHkdfGuardKmsLibrary.ErrAccessDenied =>
                (null, $"The test KEK '{DefaultWindowsServiceName}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated."),
            _ => (DefaultWindowsServiceName, string.Empty),
        };
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

/// <summary>A test that only means anything on Linux; reported as skipped elsewhere.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "Linux only.";
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
    public const string Cli = "/usr/bin/hkdfguard-v1-initialize";

    /// <summary>Needs <see cref="NativeTestEnvironment.OtherServiceVariable"/>: a second provisioned service, with its own KEK.</summary>
    public bool NeedsOtherService { get; set; }

    /// <summary>Needs the policy's provisioning allowlist (tpm.require_pinned_names), so an unlisted service has no KEK.</summary>
    public bool NeedsPinnedNamesAllowlist { get; set; }

    /// <summary>Needs the hkdfguard package's hkdfguard-v1-initialize.</summary>
    public bool NeedsCli { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? Reason(NeedsOtherService, NeedsPinnedNamesAllowlist, NeedsCli);
        set => base.Skip = value;
    }

    internal static string? Reason(bool needsOtherService = false, bool needsPinnedNamesAllowlist = false, bool needsCli = false)
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

/// <summary>The theory form of <see cref="LinuxNativeIntegrationFactAttribute"/>, with no extra requirements.</summary>
public sealed class LinuxNativeIntegrationTheoryAttribute : TheoryAttribute
{
    public override string? Skip
    {
        get => base.Skip ?? LinuxNativeIntegrationFactAttribute.Reason();
        set => base.Skip = value;
    }
}
