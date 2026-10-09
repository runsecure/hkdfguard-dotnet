using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class NativeHostTests
{
    [Fact]
    public void Library_ReturnsNonNullInstance()
    {
        var library = NativeHost.Library;

        Assert.NotNull(library);
    }

    [Fact]
    public void Library_ReturnsSameInstanceAcrossCalls()
    {
        var first = NativeHost.Library;
        var second = NativeHost.Library;

        Assert.Same(first, second);
    }

    [Fact]
    public void Library_ReturnsMatchingPlatformImplementation()
    {
        var library = NativeHost.Library;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.IsType<WindowsHkdfGuardKmsLibrary>(library);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Assert.IsType<LinuxHkdfGuardKmsLibrary>(library);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            Assert.IsType<MacOsHkdfGuardKmsLibrary>(library);
        }
        else
        {
            Assert.IsAssignableFrom<AbstractHkdfGuardKmsLibrary>(library);
        }
    }

    [Fact]
    public void Resolve_OnWindows_ReturnsTheWindowsLibrary()
        => Assert.IsType<WindowsHkdfGuardKmsLibrary>(NativeHost.Resolve(os => os == OSPlatform.Windows, "Windows"));

    [Fact]
    public void Resolve_OnLinux_ReturnsTheLinuxLibrary()
        => Assert.IsType<LinuxHkdfGuardKmsLibrary>(NativeHost.Resolve(os => os == OSPlatform.Linux, "Linux"));

    [Fact]
    public void Resolve_OnMacOs_ReturnsTheMacOsLibrary()
        => Assert.IsType<MacOsHkdfGuardKmsLibrary>(NativeHost.Resolve(os => os == OSPlatform.OSX, "macOS"));

    [Fact]
    public void Resolve_OnAnUnsupportedPlatform_ThrowsNamingIt()
    {
        var exception = Assert.Throws<PlatformNotSupportedException>(() => NativeHost.Resolve(_ => false, "FreeBSD 14"));

        Assert.Contains("FreeBSD 14", exception.Message);
    }
}
