using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>
/// Resolves the current OS's native HkdfGuard KMS library exactly once per process (binding the
/// wrong platform's library would fail on first native call anyway, so there's nothing to gain by
/// re-resolving per instance).
/// </summary>
internal static class NativeHost
{
    private static readonly Lazy<AbstractHkdfGuardKmsLibrary> LazyLibrary =
        new(() => Resolve(RuntimeInformation.IsOSPlatform, RuntimeInformation.OSDescription));

    public static AbstractHkdfGuardKmsLibrary Library => LazyLibrary.Value;

    internal static AbstractHkdfGuardKmsLibrary Resolve(Func<OSPlatform, bool> isOSPlatform, string osDescription)
    {
        if (isOSPlatform(OSPlatform.Windows))
            return new WindowsHkdfGuardKmsLibrary();

        if (isOSPlatform(OSPlatform.Linux))
            return new LinuxHkdfGuardKmsLibrary();

        if (isOSPlatform(OSPlatform.OSX))
            return new MacOsHkdfGuardKmsLibrary();

        throw new PlatformNotSupportedException(
            $"HkdfGuard.KeyWrapping.V1 has no native KMS library for '{osDescription}'.");
    }
}
