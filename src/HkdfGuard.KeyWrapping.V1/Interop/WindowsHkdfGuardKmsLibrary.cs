using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds HkdfGuardV1.dll, loaded only from %ProgramFiles%\HkdfGuard\v1 after the checks in
/// WindowsNativeLibraryLoader (see NativeLibraryResolver). It holds the per-service KEK as a
/// persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
/// Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
/// <para>
/// No call here creates a KEK: an elevated <c>hkdfguard-v1-initialize provision</c> must create it
/// first. A service name is 1-128 ASCII letters, digits or '.'.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class WindowsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "HkdfGuardV1";

    public WindowsHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    // Status codes, exactly as HkdfGuardV1's header defines them (HKDFGUARD_ERR_*).
    public const int ErrInvalidArg = -1;
    public const int ErrBufferTooSmall = -2;
    public const int ErrProvider = -3;
    public const int ErrCrypto = -4;
    public const int ErrAuthFailed = -5;
    public const int ErrMalformed = -6;
    public const int ErrInternal = -7;
    public const int ErrServiceNameInvalid = -8;
    public const int ErrInvalidPolicy = -9;
    public const int ErrGroupInvalid = -10;
    public const int ErrKekMismatch = -11;
    public const int ErrKekNotFound = -12;
    public const int ErrAccessDenied = -13;
    public const int ErrKekAclInvalid = -14;

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrInvalidArg => "invalid argument: a null pointer, wrong DEK length, or bad service",
        ErrBufferTooSmall => "the output buffer is too small for the result",
        ErrProvider => "the KEK provider or key could not be opened or created",
        ErrCrypto => "an ECDH, HKDF or AES operation failed",
        ErrAuthFailed => "AES-GCM authentication failed: the wrapped payload was altered",
        ErrMalformed => "the wrapped payload is not a valid WrappedDekV1",
        ErrInternal => "an unexpected internal failure in the native library",
        ErrServiceNameInvalid => "the service name is malformed or invalid",
        ErrInvalidPolicy => @"HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy is invalid",
        ErrGroupInvalid => @"an HKLM\Software\Policies\HkdfGuard\KeyUseGroups entry is unresolvable, not a group, or over-broad",
        ErrKekMismatch => "the payload was wrapped under a different KEK than this service's",
        ErrKekNotFound => "no KEK is provisioned for this service; run hkdfguard-v1-initialize provision",
        ErrAccessDenied => "the KEK exists, but this account is not authorized to use it; add it to the HkdfGuardUsers group or a KeyUseGroups group",
        ErrKekAclInvalid => "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal",
        _ => null,
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

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_generate_and_wrap_dek(
        string service, Span<byte> output, ref int outLen);
}
