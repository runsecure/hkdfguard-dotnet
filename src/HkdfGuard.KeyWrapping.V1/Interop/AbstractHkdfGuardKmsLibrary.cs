using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
/// unwraps a fixed-length DEK under a persistent, per-service KEK held outside the .NET process
/// (a TPM2 key, a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek /
/// hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions, and reads wrapped-key
/// files through hkdfguard_open_file. The functions are identical in shape across platforms, and
/// so are their status codes: the native header's HKDFGUARD_ERR_* table is shared number for
/// number by the Windows, Linux and macOS libraries, so it lives here, once.
/// </summary>
internal abstract class AbstractHkdfGuardKmsLibrary
{
    public const int DekLength = 32;

    // Status codes, exactly as every platform's hkdfguard.h defines them (HKDFGUARD_OK and
    // HKDFGUARD_ERR_*). Each platform band refines one of the common codes above it.

    /// <summary>The call succeeded.</summary>
    public const int Ok = 0;

    // General (-1..-7)
    public const int ErrInvalidArgument = -1;
    public const int ErrBufferTooSmall = -2;
    public const int ErrProviderUnavailable = -3;
    public const int ErrProviderError = -4;
    public const int ErrCryptoError = -5;
    public const int ErrInternalError = -6;

    // Service name and policy (-8..-9)
    public const int ErrInvalidServiceName = -8;
    public const int ErrPolicyInvalid = -9;

    // Wrapped payload (-10..-15)
    public const int ErrPayloadMalformed = -10;
    public const int ErrPayloadAuthFailed = -11;
    public const int ErrPayloadUnsupported = -12;
    public const int ErrPayloadVersionRefused = -13;

    // KEK and process (-16..-31)
    public const int ErrKekFingerprintMismatch = -16;
    public const int ErrKekNotFound = -17;
    public const int ErrKekAccessDenied = -18;
    public const int ErrKekInvalid = -19;
    public const int ErrProcessHardeningFailed = -20;

    // Key file, hkdfguard_open_file (-32..-39)
    public const int ErrFileNotFound = -32;
    public const int ErrFileAccessDenied = -33;
    public const int ErrFileIo = -34;
    public const int ErrFileTooShort = -35;
    public const int ErrFileTooLong = -36;
    public const int ErrFilePlaintextKey = -37;
    public const int ErrFileMalformed = -38;
    public const int ErrFileUntrusted = -39;

    // Windows-specific (-64..-79), refining ErrPolicyInvalid
    public const int ErrWinGroupInvalid = -64;

    // macOS-specific (-96..-111), each refining ErrProviderError
    public const int ErrMacAccessControlCreationFailed = -96;
    public const int ErrMacKeyGenerationFailed = -97;
    public const int ErrMacKeychainWriteFailed = -98;
    public const int ErrMacKekVerificationFailed = -99;
    public const int ErrMacKeychainReadFailed = -100;

    /// <summary>
    /// What a non-<see cref="Ok"/> status means, for error messages - or null when the code is
    /// unknown. The meanings are shared by every platform; a platform's binding overrides this to
    /// add what to do about a code there (which group grants access to a KEK, where the policy
    /// lives) and falls back to this for the rest.
    /// </summary>
    public virtual string? DescribeStatus(int status) => status switch
    {
        ErrInvalidArgument => "invalid argument: a null pointer, wrong DEK length, negative buffer capacity, or bad path",
        ErrBufferTooSmall => "the output buffer is too small for the result",
        ErrProviderUnavailable => "no key storage provider could be used at all",
        ErrProviderError => "the KEK provider or key could not be opened or created",
        ErrCryptoError => "an ECDH, HKDF, AES or random number operation failed",
        ErrInternalError => "an unexpected internal failure in the native library",
        ErrInvalidServiceName => "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'",
        ErrPolicyInvalid => "the machine's HkdfGuard policy is invalid",
        ErrPayloadMalformed => "the wrapped payload is not a valid wrapped DEK",
        ErrPayloadAuthFailed => "AES-GCM authentication failed: the wrapped payload was altered",
        ErrPayloadUnsupported => "the wrapped payload's version or suite is not one this native library understands",
        ErrPayloadVersionRefused => "the wrapped payload's version is one this native library understands, but this host's policy does not use",
        ErrKekFingerprintMismatch => "the payload was wrapped under a different KEK than this service's current one",
        ErrKekNotFound => "no KEK is provisioned for this service; run hkdfguard provision",
        ErrKekAccessDenied => "the KEK exists, but this account is not authorized to use it",
        ErrKekInvalid => "the existing KEK is unusable as found",
        ErrProcessHardeningFailed => "process hardening failed",
        ErrFileNotFound => "the key file, or a folder in its path, does not exist",
        ErrFileAccessDenied => "this account may not read the key file",
        ErrFileIo => "the key file is not a regular file, is in use by a writer, or could not be read",
        ErrFileTooShort => "the key file is shorter than a wrapped DEK",
        ErrFileTooLong => "the key file is longer than a wrapped DEK",
        ErrFilePlaintextKey => "the key file holds what looks like an UNWRAPPED key (32 raw bytes, or its hex or base64): treat it as a key exposure",
        ErrFileMalformed => "the key file is the right size, but is not a valid wrapped DEK",
        ErrFileUntrusted => "the key file's path is not trusted: a link or reparse point, a short or network path, or a file or folder another account could replace",
        ErrWinGroupInvalid => @"an HKLM\Software\Policies\HkdfGuard\KeyUseGroups entry is unresolvable, not a group, not host-local, or over-broad",
        ErrMacAccessControlCreationFailed => "the access policy for a new KEK could not be created",
        ErrMacKeyGenerationFailed => "the Secure Enclave refused to generate a key",
        ErrMacKeychainWriteFailed => "the new KEK could not be stored in the keychain",
        ErrMacKekVerificationFailed => "the new KEK could not be reloaded after it was stored",
        ErrMacKeychainReadFailed => "the keychain could not be read",
        _ => null,
    };

    /// <summary>
    /// Wraps <paramref name="dek"/> under the persistent KEK identified by <paramref name="service"/>.
    /// </summary>
    /// <param name="service">Non-empty, cross-platform identity of the KEK.</param>
    /// <param name="dek">The plaintext DEK to wrap (must be exactly <see cref="DekLength"/> bytes).</param>
    /// <param name="destination">Buffer to receive the wrapped payload.</param>
    /// <param name="bytesWritten">
    /// On success, the number of bytes written to <paramref name="destination"/>. On a
    /// buffer-too-small failure, the required capacity instead.
    /// </param>
    /// <returns><see cref="Ok"/> on success, or a negative error code.</returns>
    public abstract int WrapDek(string service, ReadOnlySpan<byte> dek, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Unwraps a payload previously produced by <see cref="WrapDek"/> for the same
    /// <paramref name="service"/>, recovering the original DEK.
    /// </summary>
    /// <param name="service">Must match the value used when the payload was wrapped.</param>
    /// <param name="wrapped">The wrapped payload bytes.</param>
    /// <param name="destination">Buffer to receive the recovered DEK.</param>
    /// <param name="bytesWritten">
    /// On success, always <see cref="DekLength"/>. On a buffer-too-small failure, the required
    /// capacity instead.
    /// </param>
    /// <returns><see cref="Ok"/> on success, or a negative error code.</returns>
    public abstract int UnwrapDek(string service, ReadOnlySpan<byte> wrapped, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Generates a fresh, cryptographically random DEK and immediately wraps it under the
    /// persistent KEK identified by <paramref name="service"/>. The plaintext DEK never crosses
    /// this boundary - recover it later via <see cref="UnwrapDek"/> with the same
    /// <paramref name="service"/>.
    /// </summary>
    /// <param name="service">Service Name to use with KMS operations</param>
    /// <param name="destination">Buffer to receive the wrapped payload.</param>
    /// <param name="bytesWritten">
    /// On success, the number of bytes written to <paramref name="destination"/>. On a
    /// buffer-too-small failure, the required capacity instead.
    /// </param>
    /// <returns><see cref="Ok"/> on success, or a negative error code.</returns>
    public abstract int GenerateAndWrapDek(string service, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Reads a wrapped-key file through the native library's hkdfguard_open_file, which refuses a
    /// file whose path, owner or permissions mean someone else could have replaced it, and one that
    /// holds what looks like an unwrapped key - checks only the platform can make. The bytes come
    /// back still wrapped, ready for <see cref="UnwrapDek"/>.
    /// </summary>
    /// <param name="path">The key file's path, absolute or relative to the current directory.</param>
    /// <returns>The file's wrapped payload: exactly this platform's wrapped DEK length.</returns>
    /// <exception cref="FileNotFoundException">The file, or a folder in its path, does not exist</exception>
    /// <exception cref="UnauthorizedAccessException">This account may not read the file, or its path is not trusted</exception>
    /// <exception cref="InvalidDataException">The file is the wrong size, holds what looks like an unwrapped key, or isn't a valid wrapped DEK</exception>
    /// <exception cref="IOException">The file could not be read for another reason</exception>
    /// <exception cref="ArgumentException">The path is empty, not valid UTF-8, or too long</exception>
    public byte[] OpenFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        // Every platform's wrapped DEK fits in WrappedKeyLimits.MaxBytes (Windows 132, Linux 276,
        // macOS 125 bytes), so one buffer never needs the size probe.
        var buffer = new byte[WrappedKeyLimits.MaxBytes];
        var status = OpenFile(path, buffer, out var bytesRead);
        if (status == Ok)
        {
            if (!IsWrittenWithinCapacity(bytesRead, buffer))
                throw new CryptographicException(
                    $"Native KMS open-file for key file '{path}' reported {bytesRead} bytes read into a {buffer.Length}-byte buffer; the result was discarded.");

            return buffer[..bytesRead];
        }

        var message = $"Key file '{path}' was refused by the native library with status {status} ({DescribeStatus(status) ?? "unknown status"}).";
        throw status switch
        {
            ErrFileNotFound => new FileNotFoundException(message, path),
            ErrFileAccessDenied or ErrFileUntrusted => new UnauthorizedAccessException(message),
            ErrFileTooShort or ErrFileTooLong or ErrFilePlaintextKey or ErrFileMalformed => new InvalidDataException(message),
            ErrInvalidArgument => new ArgumentException(message, nameof(path)),
            _ => new IOException(message),
        };
    }

    /// <summary>
    /// The raw hkdfguard_open_file call: reads <paramref name="path"/> into
    /// <paramref name="destination"/> without unwrapping it.
    /// </summary>
    /// <param name="bytesRead">On success, the number of bytes read.</param>
    /// <returns><see cref="Ok"/> on success, or a negative error code.</returns>
    protected abstract int OpenFile(string path, Span<byte> destination, out int bytesRead);

    /// <summary>
    /// Checks the count a successful native call reports writing against the buffer it was given,
    /// as the Go and Node bindings do: a count below zero or above the buffer's length breaks the
    /// native contract, so <paramref name="destination"/> is zeroed - it may hold part of a key -
    /// and the caller must refuse the result.
    /// </summary>
    /// <returns>True when 0 &lt;= <paramref name="written"/> &lt;= destination.Length.</returns>
    internal static bool IsWrittenWithinCapacity(int written, Span<byte> destination)
    {
        if (written >= 0 && written <= destination.Length)
            return true;

        CryptographicOperations.ZeroMemory(destination);
        return false;
    }

    /// <summary>
    /// hkdfguard_harden_process_with_flags' HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: fail unless
    /// no other process of the same user can debug or inject into this one. Same bit on every
    /// platform.
    /// </summary>
    public const uint HardenRequireProtectedSignature = 0x1u;

    /// <summary>
    /// Makes this process's memory harder to recover, through hkdfguard_harden_process_with_flags -
    /// on every platform: no crash dumps of its memory, and no debugger attach or memory reads by
    /// other processes of the same user. What that takes differs per platform; see
    /// NativeProcessHardening.
    /// </summary>
    /// <param name="flags">A bitwise OR of the HKDFGUARD_HARDEN_* flags, or 0.</param>
    /// <returns><see cref="Ok"/> on success, or a negative error code:
    /// <see cref="ErrProcessHardeningFailed"/>, or <see cref="ErrInvalidArgument"/> for an unknown flag.</returns>
    public abstract int HardenProcess(uint flags);
}
