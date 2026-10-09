using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// WinVerifyTrust with the generic Authenticode policy: checks that a file's embedded signature is
/// intact and chains to a trusted root (honouring a timestamp countersignature, so a signature made
/// while the certificate was valid stays valid). Revocation isn't checked and no network fetch is
/// made, so loading the library never blocks on a CRL or OCSP endpoint.
/// </summary>
[SupportedOSPlatform("windows")]
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to wintrust.dll; exercised by WindowsNativeLibraryLoaderTests on Windows.")]
internal static unsafe partial class WinTrust
{
    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint UiNone = 2;                    // WTD_UI_NONE
    private const uint RevokeNone = 0;                // WTD_REVOKE_NONE
    private const uint ChoiceFile = 1;                // WTD_CHOICE_FILE
    private const uint StateActionVerify = 1;         // WTD_STATEACTION_VERIFY
    private const uint StateActionClose = 2;          // WTD_STATEACTION_CLOSE
    private const uint CacheOnlyUrlRetrieval = 0x1000; // WTD_CACHE_ONLY_URL_RETRIEVAL
    private static readonly IntPtr NoInteractiveUser = new(-1); // INVALID_HANDLE_VALUE

    /// <returns>0 when the signature is valid and trusted; otherwise the WinVerifyTrust HRESULT.</returns>
    public static int VerifyEmbeddedSignature(string path)
    {
        fixed (char* filePath = path)
        {
            var file = new FileInfo
            {
                cbStruct = (uint)sizeof(FileInfo),
                pcwszFilePath = (IntPtr)filePath,
            };
            var data = new Data
            {
                cbStruct = (uint)sizeof(Data),
                dwUIChoice = UiNone,
                fdwRevocationChecks = RevokeNone,
                dwUnionChoice = ChoiceFile,
                pFile = (IntPtr)(&file),
                dwStateAction = StateActionVerify,
                dwProvFlags = CacheOnlyUrlRetrieval,
            };
            var action = GenericVerifyV2;

            var status = WinVerifyTrust(NoInteractiveUser, ref action, ref data);

            // Release the state the verify call allocated, whatever it returned.
            data.dwStateAction = StateActionClose;
            WinVerifyTrust(NoInteractiveUser, ref action, ref data);

            return status;
        }
    }

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref Data data);

    // WINTRUST_FILE_INFO
    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    // WINTRUST_DATA
    [StructLayout(LayoutKind.Sequential)]
    private struct Data
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
