using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds libhkdfguard.so.1 from the libhkdfguard1 package, loaded only from its install location
/// after the checks in <see cref="LinuxNativeLibraryLoader"/> (see NativeLibraryResolver). It
/// holds the per-service KEK on the strongest provider the root-owned policy allows - TPM2,
/// PKCS#11 or an external secret file. No Rust type, TPM handle, or OpenSSL structure ever crosses
/// this boundary, and no panic ever crosses it either: every native call below returns a plain
/// status code.
/// <para>
/// No call here creates a KEK: <c>hkdfguard-v1-initialize provision --service-name &lt;name&gt;</c>
/// must create it first, or wrap fails with <see cref="ErrKekNotFound"/>.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class LinuxHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "HkdfGuard.Kms.Linux.v1";

    public LinuxHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    // Status codes, exactly as the native library's status module defines them.
    public const int ErrInvalidArgument = -1;
    public const int ErrBufferTooSmall = -2;
    public const int ErrProviderUnavailable = -3;
    public const int ErrProviderError = -4;
    public const int ErrCryptoError = -5;
    public const int ErrInternalError = -6;
    public const int ErrInvalidUtf8 = -7;               // reserved; no longer returned (now ErrInvalidServiceName)
    public const int ErrInvalidServiceName = -8;
    public const int ErrKekNotFound = -9;
    // -10..-15 are unassigned on Linux (macOS uses them for enclave and keychain failures).
    public const int ErrFingerprintMismatch = -16;
    public const int ErrProcessHardeningFailed = -17;

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrInvalidArgument => "invalid argument: a null pointer, wrong DEK length, or negative buffer capacity",
        ErrBufferTooSmall => "the output buffer is too small for the result",
        ErrProviderUnavailable => "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
        ErrProviderError => "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
        ErrCryptoError => "the wrapped payload is malformed or failed AES-GCM authentication",
        ErrInternalError => "an unexpected internal failure in the native library",
        ErrInvalidServiceName => "the service name is malformed or invalid",
        ErrKekNotFound => "no KEK is provisioned for this service; run hkdfguard-v1-initialize provision",
        ErrFingerprintMismatch => "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed",
        ErrProcessHardeningFailed => "process hardening failed: core dumps or ptrace access could not be disabled",
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

    public override int HardenProcess() => hkdfguard_harden_process();

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_wrap_dek(
        string service, ReadOnlySpan<byte> dek, int dekLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_unwrap_dek(
        string service, ReadOnlySpan<byte> wrapped, int wrappedLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_generate_and_wrap_dek(
        string service, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName)]
    private static partial int hkdfguard_harden_process();
}
