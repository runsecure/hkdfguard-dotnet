using System.Diagnostics.CodeAnalysis;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>
/// Opt-in hardening of the whole process, through the native KMS library. DEKs pass through this
/// process's memory, so a core dump, or another process of the same user attaching a debugger or
/// reading /proc/&lt;pid&gt;/mem, could recover them. On Linux, <see cref="Apply"/> sets the core
/// dump limit to zero (hard limit included) and clears the process's dumpable flag.
/// <para>
/// It is opt-in because it is process-wide: debuggers, <c>dotnet-dump</c> and crash dumps stop
/// working for the application. Call it once, early, and after any privilege drop - the kernel
/// resets the dumpable flag when a process's credentials change. It does not stop root or a
/// process with CAP_SYS_PTRACE, and it does not keep memory out of swap; those are host settings
/// (no swap or encrypted swap, kernel.yama.ptrace_scope of 2 or 3, and for a systemd service
/// LimitCORE=0 and ProtectProc=invisible).
/// </para>
/// </summary>
public static class NativeProcessHardening
{
    /// <summary>Applies the hardening, loading the native KMS library if it isn't already.</summary>
    /// <exception cref="PlatformNotSupportedException">This platform's native library has no hardening call (only Linux's does).</exception>
    /// <exception cref="InvalidOperationException">The hardening failed; treat it as a reason not to start.</exception>
    [ExcludeFromCodeCoverage(Justification = "Hardens the whole test host, so it runs only in the opt-in NativeProcessHardeningTests case; the decision is the covered internal overload's.")]
    public static void Apply() => Apply(NativeHost.Library);

    internal static void Apply(AbstractHkdfGuardKmsLibrary library)
    {
        var status = library.HardenProcess();
        if (status == AbstractHkdfGuardKmsLibrary.Ok)
            return;

        var meaning = library.DescribeStatus(status) is { } description ? $" ({description})" : string.Empty;
        throw new InvalidOperationException($"Native process hardening failed with status {status}{meaning}.");
    }
}
