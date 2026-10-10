using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds libhkdfguard_v1.dylib (see the hkdfguard.h installed beside it), which holds the per-service KEK
/// as a Secure Enclave key. Each distinct service string gets its own, independent Secure Enclave
/// key - wrapping under one service's identifier and unwrapping under a different one fails by
/// design (<see cref="ErrFingerprintMismatch"/>). The library is installed separately - system-wide
/// at /Library/Application Support/HkdfGuard/v1, or per user at ~/.hkdfguard/v1 - and loaded only
/// from there, after the checks in <see cref="MacOsNativeLibraryLoader"/>.
/// <para>
/// No call here creates a KEK: a service must be provisioned first with
/// <c>hkdfguard-v1-initialize provision --service-name &lt;name&gt;</c>, or every wrap/unwrap fails
/// with <see cref="ErrKekNotFound"/>. A service name is 1-128 ASCII letters, digits or '.', and is
/// matched case-insensitively.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class MacOsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "hkdfguard_v1";

    public MacOsHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    // Status codes, exactly as hkdfguard.h documents them.
    public const int ErrInvalidInputLength = -1;
    public const int ErrOutputBufferTooSmall = -2;
    public const int ErrKeyUnavailable = -3;            // reserved; no longer returned
    public const int ErrPublicKeyUnavailable = -4;      // reserved; never returned
    public const int ErrEncryptionFailed = -5;
    public const int ErrDecryptionFailed = -6;
    public const int ErrUnexpectedOutputLength = -7;
    public const int ErrInvalidServiceIdentifier = -8;
    public const int ErrEnclaveUnavailable = -9;
    public const int ErrKekNotFound = -10;
    public const int ErrKekCorrupted = -11;
    public const int ErrAccessControlCreationFailed = -12;
    public const int ErrKeyGenerationFailed = -13;
    public const int ErrKeychainWriteFailed = -14;
    public const int ErrKekVerificationFailed = -15;
    public const int ErrFingerprintMismatch = -16;
    public const int ErrKeychainAccessDenied = -17;
    public const int ErrKeychainReadFailed = -18;

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrInvalidInputLength => "invalid input length, or a null buffer",
        ErrOutputBufferTooSmall => "the output buffer is too small for the result",
        ErrEncryptionFailed => "encryption failed",
        ErrDecryptionFailed => "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK",
        ErrUnexpectedOutputLength => "the native library produced an unexpected output length",
        ErrInvalidServiceIdentifier => "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'",
        ErrEnclaveUnavailable => "this Mac has no Secure Enclave",
        ErrKekNotFound => "no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision",
        ErrKekCorrupted => "the keychain item for this service can't be reconstructed into a key",
        ErrAccessControlCreationFailed => "the access policy for a new KEK could not be created",
        ErrKeyGenerationFailed => "the Secure Enclave refused to generate a key",
        ErrKeychainWriteFailed => "the new KEK could not be stored in the keychain",
        ErrKekVerificationFailed => "the new KEK could not be reloaded after it was stored",
        ErrFingerprintMismatch => "the payload was wrapped under a different KEK than this service's",
        ErrKeychainAccessDenied => "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed",
        ErrKeychainReadFailed => "the keychain could not be read",
        _ => null, // includes -3 and -4, which the header reserves and never returns
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
