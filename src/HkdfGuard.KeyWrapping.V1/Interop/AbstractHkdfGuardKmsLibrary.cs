namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
/// unwraps a fixed-length DEK under a persistent, per-service KEK held outside the .NET process
/// (a TPM2 key, a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek /
/// hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions - identical in shape
/// across platforms, but each library's negative status codes mean different things, so callers
/// must consult the concrete implementation they're using to interpret a non-<see cref="Ok"/>
/// result.
/// </summary>
internal abstract class AbstractHkdfGuardKmsLibrary
{
    public const int DekLength = 32;

    /// <summary>Status code common to every platform's native library: the call succeeded.</summary>
    public const int Ok = 0;

    /// <summary>
    /// What a non-<see cref="Ok"/> status means on this platform, for error messages - or null when
    /// the code is unknown. Status codes differ between platforms, so only the platform's own
    /// binding can say.
    /// </summary>
    public virtual string? DescribeStatus(int status) => null;

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
    /// <returns><see cref="Ok"/> on success, or a negative, implementation-specific error code.</returns>
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
    /// <returns><see cref="Ok"/> on success, or a negative, implementation-specific error code.</returns>
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
    /// <returns><see cref="Ok"/> on success, or a negative, implementation-specific error code.</returns>
    public abstract int GenerateAndWrapDek(string service, Span<byte> destination, out int bytesWritten);
}
