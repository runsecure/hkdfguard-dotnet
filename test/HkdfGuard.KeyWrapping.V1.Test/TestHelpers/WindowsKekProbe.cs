using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

/// <summary>
/// Asks the installed Windows native library whether a service's KEK exists, through its
/// <c>hkdfguard_kek_exists(const char* service, int32_t* out_exists)</c> export - so the native tests
/// can tell "not provisioned yet" (skip) apart from a real failure (run, and fail). The library is
/// loaded through the same verified loader production uses.
/// </summary>
[SupportedOSPlatform("windows")]
internal static unsafe class WindowsKekProbe
{
    /// <returns>The library's status (0 on success; see WindowsHkdfGuardKmsLibrary.Err*) and, when
    /// it succeeded, whether the KEK exists.</returns>
    public static (int Status, bool Exists) Query(string serviceName)
    {
        var handle = WindowsNativeLibraryLoader.Load();
        var kekExists = (delegate* unmanaged<byte*, int*, int>)NativeLibrary.GetExport(handle, "hkdfguard_kek_exists");

        var name = Encoding.UTF8.GetBytes(serviceName + '\0');
        int exists;
        int status;
        fixed (byte* p = name)
            status = kekExists(p, &exists);

        return (status, status == 0 && exists != 0);
    }
}
