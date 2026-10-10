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
    public void Apply_Throws_NamingTheStatusAndItsMeaning()
    {
        var library = new FakeHkdfGuardKmsLibrary
        {
            Harden = () => LinuxHkdfGuardKmsLibrary.ErrProcessHardeningFailed,
            Describe = s => s == LinuxHkdfGuardKmsLibrary.ErrProcessHardeningFailed ? "could not disable core dumps" : null,
        };

        var ex = Assert.Throws<InvalidOperationException>(() => NativeProcessHardening.Apply(library));

        Assert.Contains("-17", ex.Message);
        Assert.Contains("could not disable core dumps", ex.Message);
    }

    [Fact]
    public void Apply_Throws_WithJustTheStatus_WhenItsMeaningIsUnknown()
    {
        var library = new FakeHkdfGuardKmsLibrary { Harden = () => -99 };

        var ex = Assert.Throws<InvalidOperationException>(() => NativeProcessHardening.Apply(library));

        Assert.EndsWith("status -99.", ex.Message);
    }

    [Fact]
    public void Apply_OnAPlatformWithoutIt_IsNotSupported()
    {
        var ex = Assert.Throws<PlatformNotSupportedException>(() => NativeProcessHardening.Apply(new FakeHkdfGuardKmsLibrary()));

        Assert.Contains("Linux", ex.Message);
    }

    [Fact]
    public void TheWindowsAndMacOsLibraries_HaveNoHardeningCall()
    {
        Assert.Throws<PlatformNotSupportedException>(() => new WindowsHkdfGuardKmsLibrary().HardenProcess());
        Assert.Throws<PlatformNotSupportedException>(() => new MacOsHkdfGuardKmsLibrary().HardenProcess());
    }

    /// <summary>
    /// Hardens this very test process, so it only runs when asked for:
    /// HKDFGUARD_TEST_PROCESS_HARDENING=1 on Linux with the package installed. Afterwards no
    /// debugger can attach to the test host and it writes no core dump.
    /// </summary>
    [ProcessHardeningFact]
    public void Apply_OnLinux_DisablesCoreDumpsAndClearsTheDumpableFlag()
    {
        NativeProcessHardening.Apply();

        Assert.Equal(0, prctl(PrGetDumpable, 0, 0, 0, 0));
        Span<ulong> limit = stackalloc ulong[2];
        Assert.Equal(0, getrlimit(RlimitCore, ref limit[0]));
        Assert.Equal(0UL, limit[0]); // soft
        Assert.Equal(0UL, limit[1]); // hard
    }

    private const int PrGetDumpable = 3;
    private const int RlimitCore = 4;

    [LibraryImport("libc.so.6")]
    private static partial int prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);

    [LibraryImport("libc.so.6")]
    private static partial int getrlimit(int resource, ref ulong limits);
}

public sealed class ProcessHardeningFactAttribute : FactAttribute
{
    public const string Variable = "HKDFGUARD_TEST_PROCESS_HARDENING";

    public ProcessHardeningFactAttribute()
    {
        if (Environment.GetEnvironmentVariable(Variable) != "1")
            Skip = $"Hardens the test process itself; set {Variable}=1 to run it.";
        else if (InstalledLinuxLibraryFactAttribute.InstalledPath is null)
            Skip = "Needs the Linux native library (libhkdfguard1) installed.";
    }
}
