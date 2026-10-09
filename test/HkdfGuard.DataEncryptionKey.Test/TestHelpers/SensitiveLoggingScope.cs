using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// Temporarily sets HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging, restoring the
/// original value on Dispose - so a test can exercise a production method's "if enabled, log"
/// branch without leaking that shared static flag into other tests. Safe only because this
/// assembly disables test parallelization (see AssemblyInfo.cs) - EnableSensitiveLogging has no
/// synchronization of its own.
/// </summary>
internal readonly struct SensitiveLoggingScope : IDisposable
{
    private readonly bool _original;

    public SensitiveLoggingScope(bool enabled)
    {
        _original = HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging;
        HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging = enabled;
    }

    public void Dispose() => HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging = _original;
}
