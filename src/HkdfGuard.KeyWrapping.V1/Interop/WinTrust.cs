using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// WinVerifyTrust with the generic Authenticode policy. <see cref="VerifyEmbeddedSignature"/> checks
/// that a file's embedded signature is intact and chains to a trusted root (honouring a timestamp
/// countersignature, so a signature made while the certificate was valid stays valid), with no
/// revocation check and no network fetch; the signer's certificate chain - the one WinVerifyTrust
/// itself built and validated - is handed back for the caller's own checks.
/// <see cref="CheckRevocation"/> is a second, separate pass that checks only revocation, network
/// allowed; <see cref="WindowsRevocationPolicy"/> decides what its result means.
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
    private const uint RevokeWholeChain = 1;          // WTD_REVOKE_WHOLECHAIN
    private const uint StateActionIgnore = 0;         // WTD_STATEACTION_IGNORE
    private const uint RevocationCheckChainExcludeRoot = 0x80; // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    private const int NoSignerCert = unchecked((int)0x80096002); // TRUST_E_NO_SIGNER_CERT
    private static readonly IntPtr NoInteractiveUser = new(-1); // INVALID_HANDLE_VALUE

    /// <param name="path">The signed file.</param>
    /// <param name="signerChain">When 0 is returned, the signer's chain as WinVerifyTrust validated it, leaf first; otherwise null.</param>
    /// <returns>0 when the signature is valid and trusted; otherwise the WinVerifyTrust HRESULT.</returns>
    public static int VerifyEmbeddedSignature(string path, out X509Chain? signerChain)
    {
        signerChain = null;
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
            try
            {
                if (status == 0)
                {
                    signerChain = DuplicateSignerChain(data.hWVTStateData);
                    if (signerChain is null)
                        status = NoSignerCert;
                }
            }
            finally
            {
                // Release the state the verify call allocated, whatever it returned.
                data.dwStateAction = StateActionClose;
                WinVerifyTrust(NoInteractiveUser, ref action, ref data);
            }

            return status;
        }
    }

    /// <summary>
    /// Verifies the signature again, this time checking every certificate in the chain below the
    /// root for revocation, fetching revocation information over the network if it isn't cached.
    /// No state is kept, so there is nothing to release. Not lifetime signing: a timestamped
    /// signature stays valid after its short-lived certificate expires.
    /// </summary>
    /// <param name="path">The signed file, already accepted by <see cref="VerifyEmbeddedSignature"/>.</param>
    /// <returns>The WinVerifyTrust HRESULT; see <see cref="WindowsRevocationPolicy.Refuses"/>.</returns>
    public static int CheckRevocation(string path)
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
                fdwRevocationChecks = RevokeWholeChain,
                dwUnionChoice = ChoiceFile,
                pFile = (IntPtr)(&file),
                dwStateAction = StateActionIgnore,
                dwProvFlags = RevocationCheckChainExcludeRoot,
            };
            var action = GenericVerifyV2;
            return WinVerifyTrust(NoInteractiveUser, ref action, ref data);
        }
    }

    // The primary signer's chain context, read from the verify call's state before it is released.
    // X509Chain(IntPtr) duplicates the context (CertDuplicateCertificateChain), so the result
    // outlives that state. Null if any link is missing.
    private static X509Chain? DuplicateSignerChain(IntPtr stateData)
    {
        var provider = WTHelperProvDataFromStateData(stateData);
        if (provider == IntPtr.Zero)
            return null;

        var signer = (ProviderSigner*)WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if (signer == null || signer->cbStruct < sizeof(ProviderSigner) || signer->pChainContext == IntPtr.Zero)
            return null;

        return new X509Chain(signer->pChainContext);
    }

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref Data data);

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial IntPtr WTHelperGetProvSignerFromChain(IntPtr providerData, uint signerIndex, int counterSigner, uint counterSignerIndex);

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

    // CRYPT_PROVIDER_SGNR; pChainContext is its last member.
    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderSigner
    {
        public uint cbStruct;
        public uint sftVerifyAsOfLow; // FILETIME
        public uint sftVerifyAsOfHigh;
        public uint csCertChain;
        public IntPtr pasCertChain;
        public uint dwSignerType;
        public IntPtr psSigner;
        public uint dwError;
        public uint csCounterSigners;
        public IntPtr pasCounterSigners;
        public IntPtr pChainContext;
    }
}
