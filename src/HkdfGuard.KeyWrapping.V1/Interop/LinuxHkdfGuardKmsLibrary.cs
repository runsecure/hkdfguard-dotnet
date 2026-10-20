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
/// No call here creates a KEK: <c>hkdfguard provision --service-name &lt;name&gt;</c>
/// must create it first, or wrap fails with <see cref="AbstractHkdfGuardKmsLibrary.ErrKekNotFound"/>.
/// </para>
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin P/Invoke binding to the native KMS library, which only exists on its own OS; exercised by NativeKeyWrappingIntegrationTests where present.")]
internal sealed partial class LinuxHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    // Never resolved by name: NativeLibraryResolver maps it to the one verified install path.
    internal const string LibraryName = "HkdfGuard.Kms.Linux.v1";

    public LinuxHkdfGuardKmsLibrary() => NativeLibraryResolver.EnsureRegistered();

    /// <inheritdoc/>
    public override string? DescribeStatus(int status) => status switch
    {
        ErrProviderUnavailable => "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
        ErrProviderError => "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
        ErrPolicyInvalid => "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, or a provider this build lacks",
        ErrKekNotFound => "no KEK is provisioned for this service; run hkdfguard provision",
        ErrKekFingerprintMismatch => "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed",
        ErrProcessHardeningFailed => "process hardening failed: core dumps or ptrace access could not be disabled",
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

    [LibraryImport(LibraryName)]
    private static partial int hkdfguard_harden_process_with_flags(uint flags);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_open_file(string path, Span<byte> output, ref int outLen);
}
