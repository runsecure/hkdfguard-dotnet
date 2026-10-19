using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds libhkdfguard_v1.dylib (see the hkdfguard.h installed beside it), which holds the per-service KEK
/// as a Secure Enclave key. Each distinct service string gets its own, independent Secure Enclave
/// key - wrapping under one service's identifier and unwrapping under a different one fails by
/// design (<see cref="AbstractHkdfGuardKmsLibrary.ErrKekFingerprintMismatch"/>). The library is installed separately - system-wide
/// at /Library/Application Support/HkdfGuard/v1, or per user at ~/.hkdfguard/v1 - and loaded only
/// from there, after the checks in <see cref="MacOsNativeLibraryLoader"/>.
/// <para>
/// No call here creates a KEK: a service must be provisioned first with
/// <c>hkdfguard-v1-initialize provision --service-name &lt;name&gt;</c>, or every wrap/unwrap fails
/// with <see cref="AbstractHkdfGuardKmsLibrary.ErrKekNotFound"/>. A service name is 1-128 ASCII letters, digits or '.', and is
/// matched case-insensitively.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class MacOsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "hkdfguard_v1";

    public MacOsHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrProviderUnavailable => "this Mac has no Secure Enclave",
        ErrPayloadAuthFailed => "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK",
        ErrKekNotFound => "no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision",
        ErrKekAccessDenied => "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed",
        ErrKekInvalid => "the keychain item for this service can't be reconstructed into a key",
        ErrProcessHardeningFailed => "process hardening failed: core dumps or debugger attachment could not be denied, or (with RequireProtectedSignature) the host executable's code signature still allows it - it needs the Hardened Runtime, without get-task-allow or DYLD_* entitlements",
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

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_wrap_dek(
        string service, ReadOnlySpan<byte> dek, int dekLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_unwrap_dek(
        string service, ReadOnlySpan<byte> wrapped, int wrappedLen, Span<byte> output, ref int outLen);

    public override int HardenProcess(uint flags) => hkdfguard_harden_process_with_flags(flags);

    protected override int OpenFile(string path, Span<byte> destination, out int bytesRead)
    {
        var outLen = destination.Length;
        var status = hkdfguard_open_file(path, destination, ref outLen);
        bytesRead = outLen;
        return status;
    }

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_generate_and_wrap_dek(
        string service, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_open_file(string path, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName)]
    private static partial int hkdfguard_harden_process_with_flags(uint flags);
}
