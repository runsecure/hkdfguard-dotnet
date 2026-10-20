using System.Diagnostics.CodeAnalysis;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>How strict <see cref="NativeProcessHardening.Apply(ProcessHardeningOptions)"/> is.</summary>
[Flags]
public enum ProcessHardeningOptions
{
    /// <summary>Harden as far as this process allows; on macOS a weak code signature is only logged.</summary>
    None = 0,

    /// <summary>
    /// Fail unless no other process of the same user can attach a debugger to, or inject code into,
    /// this process - what the native command-line tools themselves require. On Windows it also
    /// closes everything the process creates afterwards (threads, child processes, named pipes and
    /// other named objects) to its own user, so use it in a service that shares no objects with
    /// other processes by name. On macOS it fails unless the host executable is signed with the
    /// Hardened Runtime and without the get-task-allow or DYLD_* entitlements, so unsigned hosts
    /// (dotnet itself, Debug builds) can't use it. On Linux it adds nothing: the plain call already
    /// guarantees it.
    /// </summary>
    RequireProtectedSignature = 1,
}

/// <summary>
/// Opt-in hardening of the whole process, through the native KMS library's
/// hkdfguard_harden_process_with_flags. DEKs pass through this process's memory, so a crash dump,
/// or another process of the same user attaching a debugger or reading its memory, could recover
/// them. The native library never does this on its own: it changes process-wide state the
/// application owns. What it does:
/// <list type="bullet">
/// <item><b>Windows:</b> crash reports leave out the heap (WerSetFlags NOHEAP), and the process's
/// and its existing threads' access lists are replaced so that only SYSTEM may read or write its
/// memory, inject threads or duplicate its handles - the account it runs as keeps only query,
/// synchronize and terminate. Threads started later keep the default access unless
/// <see cref="ProcessHardeningOptions.RequireProtectedSignature"/> is passed; call it early, before
/// starting worker threads.</item>
/// <item><b>Linux:</b> the core dump limit is set to zero (hard limit included) and the process's
/// dumpable flag is cleared, which also stops ptrace and /proc/&lt;pid&gt;/mem access by other
/// processes of the same user.</item>
/// <item><b>macOS:</b> core dumps are disabled and debugger attachment is denied; the host
/// executable's code signature decides whether code injection is possible, which the library can
/// check but not change.</item>
/// </list>
/// <para>
/// It is opt-in because it is process-wide: debuggers, <c>dotnet-dump</c> and crash dumps stop
/// working for the application. Call it once, early, and after any privilege drop (on Linux the
/// kernel resets the dumpable flag when a process's credentials change). It is a same-user barrier:
/// it does not stop administrators, root, SYSTEM, a process with CAP_SYS_PTRACE or
/// SeDebugPrivilege, or the kernel, and it does not keep memory out of swap, the page file or
/// hibernation files; those are host settings.
/// </para>
/// </summary>
public static class NativeProcessHardening
{
    /// <summary>Applies the hardening, loading the native KMS library if it isn't already.</summary>
    /// <exception cref="InvalidOperationException">The hardening failed; treat it as a reason not to start.</exception>
    [ExcludeFromCodeCoverage(Justification = "Hardens the whole test host, so it runs only in the opt-in NativeProcessHardeningTests case; the decision is the covered internal overload's.")]
    public static void Apply() => Apply(ProcessHardeningOptions.None);

    /// <summary>Applies the hardening with <paramref name="options"/>, loading the native KMS library if it isn't already.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="options"/> has a flag this library doesn't define.</exception>
    /// <exception cref="InvalidOperationException">The hardening failed, or the process can't meet
    /// <see cref="ProcessHardeningOptions.RequireProtectedSignature"/>; treat it as a reason not to start.</exception>
    [ExcludeFromCodeCoverage(Justification = "Hardens the whole test host, so it runs only in the opt-in NativeProcessHardeningTests case; the decision is the covered internal overload's.")]
    public static void Apply(ProcessHardeningOptions options) => Apply(NativeHost.Library, options);

    internal static void Apply(AbstractHkdfGuardKmsLibrary library, ProcessHardeningOptions options = ProcessHardeningOptions.None)
    {
        // Checked here so an unknown flag never reaches native code, which would refuse it anyway.
        if ((options & ~ProcessHardeningOptions.RequireProtectedSignature) != 0)
            throw new ArgumentOutOfRangeException(nameof(options), options, "Unknown process hardening option.");

        var flags = options.HasFlag(ProcessHardeningOptions.RequireProtectedSignature)
            ? AbstractHkdfGuardKmsLibrary.HardenRequireProtectedSignature
            : 0u;

        var status = library.HardenProcess(flags);
        if (status == AbstractHkdfGuardKmsLibrary.Ok)
            return;

        var meaning = library.DescribeStatus(status) is { } description ? $" ({description})" : string.Empty;
        throw new InvalidOperationException($"Native process hardening failed with status {status}{meaning}.");
    }
}
