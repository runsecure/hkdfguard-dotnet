using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
/// provider on the host - TPM2 > PKCS#11 > external secret > software > ephemeral - to hold the
/// per-service KEK. No Rust type, TPM handle, or OpenSSL structure ever crosses this boundary, and
/// no panic ever crosses it either: every native call below returns a plain status code.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class LinuxHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    private const string LibraryName = "HkdfGuardKeyProtectionLinux";

    public LinuxHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    public const int ErrInvalidArgument = -1;
    public const int ErrBufferTooSmall = -2;
    public const int ErrProviderUnavailable = -3;
    public const int ErrProviderError = -4;
    public const int ErrCryptoError = -5;
    public const int ErrInternalError = -6;
    public const int ErrInvalidUtf8 = -7;
    public const int ErrMissingServiceName = -8;

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
