using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

public partial class NativeProcessHardeningTests
{
    [Fact]
    public void Apply_Succeeds_WhenTheLibraryReportsOk()
    {
        var library = new FakeHkdfGuardKmsLibrary { Harden = () => AbstractHkdfGuardKmsLibrary.Ok };

        NativeProcessHardening.Apply(library);

        Assert.Equal(1, library.HardenCallCount);
    }

    [Fact]
    public void Apply_ByDefault_PassesNoFlags()
    {
        var library = new FakeHkdfGuardKmsLibrary();

        NativeProcessHardening.Apply(library);

        Assert.Equal(0u, library.LastHardenFlags);
    }

    [Fact]
    public void Apply_RequireProtectedSignature_PassesTheNativeFlag()
    {
        var library = new FakeHkdfGuardKmsLibrary();

        NativeProcessHardening.Apply(library, ProcessHardeningOptions.RequireProtectedSignature);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.HardenRequireProtectedSignature, library.LastHardenFlags);
        Assert.Equal(0x1u, AbstractHkdfGuardKmsLibrary.HardenRequireProtectedSignature);
        Assert.Equal(1, (int)ProcessHardeningOptions.RequireProtectedSignature);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(-1)]
    public void Apply_RefusesAnUnknownOption_BeforeReachingTheNativeLibrary(int options)
    {
        var library = new FakeHkdfGuardKmsLibrary();

        Assert.Throws<ArgumentOutOfRangeException>(() => NativeProcessHardening.Apply(library, (ProcessHardeningOptions)options));
        Assert.Equal(0, library.HardenCallCount);
    }

    [Fact]
    public void Apply_Throws_NamingTheStatusAndItsMeaning()
    {
        var library = new FakeHkdfGuardKmsLibrary
        {
            Harden = () => AbstractHkdfGuardKmsLibrary.ErrProcessHardeningFailed,
            Describe = s => s == AbstractHkdfGuardKmsLibrary.ErrProcessHardeningFailed ? "could not disable core dumps" : null,
        };

        var ex = Assert.Throws<InvalidOperationException>(() => NativeProcessHardening.Apply(library));

        Assert.Contains("-20", ex.Message);
        Assert.Contains("could not disable core dumps", ex.Message);
    }

    [Fact]
    public void Apply_Throws_WithJustTheStatus_WhenItsMeaningIsUnknown()
    {
        var library = new FakeHkdfGuardKmsLibrary { Harden = () => -150 };

        var ex = Assert.Throws<InvalidOperationException>(() => NativeProcessHardening.Apply(library));

        Assert.EndsWith("status -150.", ex.Message);
    }

    [Theory]
    [InlineData("Windows", "access lists")]
    [InlineData("Linux", "ptrace")]
    [InlineData("macOS", "Hardened Runtime")]
    public void EachPlatform_DescribesAHardeningFailureInItsOwnTerms(string platform, string hint)
    {
        AbstractHkdfGuardKmsLibrary library = platform switch
        {
            "Windows" => new WindowsHkdfGuardKmsLibrary(),
            "Linux" => new LinuxHkdfGuardKmsLibrary(),
            _ => new MacOsHkdfGuardKmsLibrary(),
        };

        Assert.Contains(hint, library.DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrProcessHardeningFailed));
    }

    /// <summary>
    /// Hardens this very test process, so it only runs when asked for:
    /// HKDFGUARD_TEST_PROCESS_HARDENING=1 on Linux with the package installed. Afterwards no
    /// debugger can attach to the test host and it writes no core dump.
    /// </summary>
    [ProcessHardeningFact(ProcessHardeningFactAttribute.Linux)]
    public void Apply_OnLinux_DisablesCoreDumpsAndClearsTheDumpableFlag()
    {
        NativeProcessHardening.Apply();

        Assert.Equal(0, prctl(PrGetDumpable, 0, 0, 0, 0));
        Span<ulong> limit = stackalloc ulong[2];
        Assert.Equal(0, getrlimit(RlimitCore, ref limit[0]));
        Assert.Equal(0UL, limit[0]); // soft
        Assert.Equal(0UL, limit[1]); // hard
    }

    /// <summary>
    /// Hardens this very test process, so it only runs when asked for:
    /// HKDFGUARD_TEST_PROCESS_HARDENING=1 on Windows with the native library installed. The
    /// process's access list then grants its own account only query, synchronize and terminate -
    /// so even this process, asking without SeDebugPrivilege, can no longer open itself to read its
    /// memory, though it can still query it.
    /// </summary>
    [ProcessHardeningFact(ProcessHardeningFactAttribute.Windows)]
    public void Apply_OnWindows_ClosesTheProcessToItsOwnAccount()
    {
        const uint processVmRead = 0x0010;
        const uint processQueryLimitedInformation = 0x1000;
        const int errorAccessDenied = 5;

        NativeProcessHardening.Apply();

        var readable = OpenProcess(processVmRead, false, (uint)Environment.ProcessId);
        var lastError = Marshal.GetLastPInvokeError();
        if (readable != IntPtr.Zero)
            CloseHandle(readable);
        Assert.Equal(IntPtr.Zero, readable);
        Assert.Equal(errorAccessDenied, lastError);

        var queryable = OpenProcess(processQueryLimitedInformation, false, (uint)Environment.ProcessId);
        Assert.NotEqual(IntPtr.Zero, queryable);
        CloseHandle(queryable);

        // This thread existed when the hardening ran, so it is closed too.
        Assert.Equal(errorAccessDenied, OpenThreadContext(GetCurrentThreadId()));

        // Idempotent: hardening an already hardened process succeeds.
        NativeProcessHardening.Apply();
    }

    /// <summary>
    /// The strict form, on Windows: a console process sharing no named objects - this test host -
    /// can meet RequireProtectedSignature, and threads started afterwards are closed too.
    /// </summary>
    [ProcessHardeningFact(ProcessHardeningFactAttribute.Windows)]
    public void Apply_OnWindows_WithRequireProtectedSignature_Succeeds_AndClosesLaterThreadsToo()
    {
        const uint processVmRead = 0x0010;
        const int errorAccessDenied = 5;

        NativeProcessHardening.Apply(ProcessHardeningOptions.RequireProtectedSignature);

        var readable = OpenProcess(processVmRead, false, (uint)Environment.ProcessId);
        if (readable != IntPtr.Zero)
            CloseHandle(readable);
        Assert.Equal(IntPtr.Zero, readable);

        // A thread started after the hardening - certainly a new OS thread - is closed too.
        Assert.Equal(errorAccessDenied, WithNewThread(OpenThreadContext));
    }

    /// <summary>OpenThread(THREAD_GET_CONTEXT) on <paramref name="threadId"/>: 0 if it opened (the handle is closed), else the error.</summary>
    private static int OpenThreadContext(uint threadId)
    {
        const uint threadGetContext = 0x0008;

        var handle = OpenThread(threadGetContext, false, threadId);
        if (handle == IntPtr.Zero)
            return Marshal.GetLastPInvokeError();
        CloseHandle(handle);
        return 0;
    }

    /// <summary>Starts a new thread and returns <paramref name="check"/> of its id, while it is still running.</summary>
    private static int WithNewThread(Func<uint, int> check)
    {
        using var started = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        uint id = 0;
        var thread = new Thread(() =>
        {
            id = GetCurrentThreadId();
            started.Set();
            release.Wait();
        });
        thread.Start();
        try
        {
            started.Wait();
            return check(id);
        }
        finally
        {
            release.Set();
            thread.Join();
        }
    }

    private const int PrGetDumpable = 3;
    private const int RlimitCore = 4;

    [LibraryImport("libc.so.6")]
    private static partial int prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);

    [LibraryImport("libc.so.6")]
    private static partial int getrlimit(int resource, ref ulong limits);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenThread(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint threadId);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetCurrentThreadId();
}

/// <summary>
/// A test that hardens the test process itself, so it runs only with
/// HKDFGUARD_TEST_PROCESS_HARDENING=1, on its platform, with that platform's native library installed.
/// </summary>
public sealed class ProcessHardeningFactAttribute : FactAttribute
{
    public const string Variable = "HKDFGUARD_TEST_PROCESS_HARDENING";
    public const string Linux = "Linux";
    public const string Windows = "Windows";

    public ProcessHardeningFactAttribute(string platform)
    {
        if (Environment.GetEnvironmentVariable(Variable) != "1")
            Skip = $"Hardens the test process itself; set {Variable}=1 to run it.";
        else if (platform == Linux && !OperatingSystem.IsLinux() || platform == Windows && !OperatingSystem.IsWindows())
            Skip = $"{platform} only.";
        else if (platform == Linux && InstalledLinuxLibraryFactAttribute.InstalledPath is null)
            Skip = "Needs the Linux native library (libhkdfguard1) installed.";
        else if (platform == Windows && !File.Exists(WindowsNativeLibraryLoader.InstalledPath))
            Skip = $"Needs the Windows native library installed at {WindowsNativeLibraryLoader.InstalledPath}.";
    }
}
