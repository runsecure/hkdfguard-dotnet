using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// This assembly's DllImport resolver. It sends the native KMS library to the platform's loader -
/// <see cref="WindowsNativeLibraryLoader"/> on Windows, <see cref="MacOsNativeLibraryLoader"/> on
/// macOS, <see cref="LinuxNativeLibraryLoader"/> on Linux - which load it only from its verified
/// install location; a failed verification throws rather than falling back to the default search.
/// Every other import gets the runtime's default resolution.
/// <para>
/// Every concrete KMS binding registers this in its constructor, so it is always in place before
/// the first native call. A resolver can be set only once per assembly; registration is idempotent,
/// and no caller returns until it has actually happened (see <see cref="RegistrationGate"/>).
/// </para>
/// </summary>
internal static class NativeLibraryResolver
{
    private static readonly RegistrationGate Registration = new();

    /// <summary>
    /// Installs the resolver if it isn't already. Returns only once it is installed - including
    /// for a caller that arrives while another thread is still installing it - so the native call
    /// that follows can never be resolved by the default search instead.
    /// </summary>
    public static void EnsureRegistered()
        => Registration.Run(() => NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve));

    /// <summary>
    /// Runs an install action exactly once, and makes every caller wait until it has completed.
    /// A flag set before the work is done (the obvious Interlocked.Exchange pattern) would let a
    /// second caller return while the first is still installing. If the action throws, nothing is
    /// recorded, so the next call tries again.
    /// </summary>
    internal sealed class RegistrationGate
    {
        private readonly Lock _gate = new();
        private volatile bool _done;

        public bool IsDone => _done;

        public void Run(Action install)
        {
            if (_done)
                return;

            lock (_gate)
            {
                if (_done)
                    return;

                install();
                _done = true;
            }
        }
    }

    internal static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        => Route(libraryName, RuntimeInformation.IsOSPlatform, LoadWindows, LoadMacOs, LoadLinux);

    /// <summary>
    /// The routing decision, with the platform check and the loaders passed in so every branch can
    /// be tested on any platform: the platform's own KMS library goes to that platform's loader; a
    /// KMS library name on the wrong platform is refused, so the runtime never falls back to its
    /// default search (the application folder, PATH) for a file by that name; every other import
    /// gets the default (zero).
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">libraryName is another platform's KMS library</exception>
    internal static IntPtr Route(string libraryName, Func<OSPlatform, bool> isPlatform, Func<IntPtr> loadWindows, Func<IntPtr> loadMacOs, Func<IntPtr> loadLinux)
    {
        if (libraryName == WindowsHkdfGuardKmsLibrary.LibraryName)
            return isPlatform(OSPlatform.Windows) ? loadWindows() : throw WrongPlatform(libraryName);

        if (libraryName == MacOsHkdfGuardKmsLibrary.LibraryName)
            return isPlatform(OSPlatform.OSX) ? loadMacOs() : throw WrongPlatform(libraryName);

        if (libraryName == LinuxHkdfGuardKmsLibrary.LibraryName)
            return isPlatform(OSPlatform.Linux) ? loadLinux() : throw WrongPlatform(libraryName);

        return IntPtr.Zero;
    }

    private static PlatformNotSupportedException WrongPlatform(string libraryName)
        => new($"The HkdfGuard KMS library '{libraryName}' is another platform's; it is never loaded here, nor searched for.");

    // Only ever invoked by Route after the matching platform check.
#pragma warning disable CA1416
    private static IntPtr LoadWindows() => WindowsNativeLibraryLoader.Load();

    [ExcludeFromCodeCoverage(Justification = "Runs only on macOS; Route's macOS branch is covered with a stand-in loader.")]
    private static IntPtr LoadMacOs() => MacOsNativeLibraryLoader.Load();

    [ExcludeFromCodeCoverage(Justification = "Runs only on Linux; Route's Linux branch is covered with a stand-in loader.")]
    private static IntPtr LoadLinux() => LinuxNativeLibraryLoader.Load();
#pragma warning restore CA1416
}
