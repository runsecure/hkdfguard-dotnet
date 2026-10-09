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
            return (null, $"Set {ServiceVariable} to a service provisioned with hkdfguard-v1-initialize to run native integration tests.");

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
