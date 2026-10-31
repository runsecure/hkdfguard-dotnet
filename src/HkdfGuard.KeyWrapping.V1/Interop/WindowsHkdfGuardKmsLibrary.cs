using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds HkdfGuard.dll, loaded only from %ProgramFiles%\HkdfGuard\v1 after the checks in
/// WindowsNativeLibraryLoader (see NativeLibraryResolver). It holds the per-service KEK as a
/// persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
/// Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
/// <para>
/// No call here creates a KEK: an elevated <c>hkdfguard provision</c> must create it first. A
/// service name is 1-128 ASCII letters, digits or '.'.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class WindowsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "HkdfGuard.Kms.Windows.v1";

    public WindowsHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrProviderUnavailable => @"payload version 2 is unavailable on this host: the TPM can't be used for it and KeyStoragePolicy, or an existing TPM KEK, rules out the software key store (event 2008 names the reason); set HKLM\Software\Policies\HkdfGuard\ClassicalMode to 1 to keep using version 1",
        ErrProviderError => "the KEK's key storage provider (Platform Crypto Provider or Software KSP) could not open or create the key",
        ErrPolicyInvalid => @"a machine policy value under HKLM\Software\Policies\HkdfGuard is invalid",
        ErrPayloadVersionRefused => @"the wrapped payload is the other payload version from the one HKLM\Software\Policies\HkdfGuard\ClassicalMode selects (absent or 0: version 2; 1: version 1); a host unwraps only its own version",
        ErrKekNotFound => "no KEK is provisioned for this service; run hkdfguard provision from an elevated prompt",
        ErrKekAccessDenied => "the KEK exists, but this account is not authorized to use it (or, for a new KEK, the process is not elevated); add it to the HkdfGuardUsers group or a KeyUseGroups group",
        ErrKekInvalid => "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal",
        ErrProcessHardeningFailed => "process hardening failed: the crash-report heap exclusion or the process and thread access lists could not be set, or (with RequireProtectedSignature) the process could not be closed to its own user",
        _ => base.DescribeStatus(status),
    };

    public override int WrapDek(string service, ReadOnlySpan<byte> dek, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_wrap_dek(service, dek, dek.Length, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    public override int UnwrapDek(string service, ReadOnlySpan<byte> wrapped, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_unwrap_dek(service, wrapped, wrapped.Length, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    public override int GenerateAndWrapDek(string service, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_generate_and_wrap_dek(service, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    public override int HardenProcess(uint flags) => hkdfguard_harden_process_with_flags(flags);

    protected override int OpenFile(string path, Span<byte> destination, out int bytesRead)
    {
        var outLen = destination.Length;
        var status = hkdfguard_open_file(path, destination, ref outLen);
        bytesRead = outLen;
        return status;
    }

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_wrap_dek(
        string service, ReadOnlySpan<byte> dek, int dekLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_unwrap_dek(
        string service, ReadOnlySpan<byte> wrapped, int wrappedLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_generate_and_wrap_dek(
        string service, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_open_file(string path, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName)]
    private static partial int hkdfguard_harden_process_with_flags(uint flags);
}
