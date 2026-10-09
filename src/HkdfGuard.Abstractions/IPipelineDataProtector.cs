namespace HkdfGuard.Abstractions;

/// <summary>
/// A short-lived, string-level protector for a pipeline that must encrypt secrets before a durable
/// KEK exists. Unlike IDataProtector, it is not bound to one purpose: every Encrypt/Decrypt names
/// the secret it's protecting, so one instance - and therefore one key - can protect many secrets,
/// each bound to its own identifier. It owns a single in-memory key for its whole lifetime, stamps
/// every value with <see cref="KeyVersion"/>, and exposes that key once the pipeline is done so it
/// can be wrapped under a real KEK.
/// <para>
/// The secret identifier is the configuration key the value will be stored under - its full path,
/// e.g. "ConnectionStrings:Admin". It's bound into the value as Additional Authenticated Data via
/// ProtectedConfigurationPurpose, the same rule ProtectedConfigurationRoot reads with, so once this
/// key is wrapped and registered at <see cref="KeyVersion"/>, <c>root.Decrypt(secretIdentifier)</c>
/// reveals the value - and a value copied under any other key fails authentication. Identifiers
/// are case-insensitive for ASCII letters only (see ProtectedConfigurationPurpose).
/// </para>
/// </summary>
public interface IPipelineDataProtector : IDisposable
{
    /// <summary>The version stamped on every value - the version this key will be registered under.</summary>
    public int KeyVersion { get; }

    /// <summary>
    /// Encrypts plaintext bound to <paramref name="secretIdentifier"/>, and formats the result via
    /// the configured IEncryptedFormatProvider.
    /// </summary>
    /// <param name="plaintext">The secret to protect. Read-only, so it is not zeroed: the caller
    /// owns it and should clear it once done (its UTF-8 copy inside this call is zeroed).</param>
    /// <param name="secretIdentifier">The configuration key the value will be stored under (full
    /// path, e.g. "ConnectionStrings:Admin"); Decrypt must name the same secret</param>
    /// <returns>The formatted, encrypted string</returns>
    /// <exception cref="ArgumentException">secretIdentifier is empty</exception>
    public string Encrypt(ReadOnlySpan<char> plaintext, ReadOnlySpan<char> secretIdentifier);

    /// <summary>
    /// Parses and decrypts a formatted value directly into result, verifying it was encrypted for
    /// <paramref name="secretIdentifier"/> - never materializes the plaintext as a string.
    /// </summary>
    /// <param name="encrypted">The formatted, encrypted string</param>
    /// <param name="secretIdentifier">The configuration key the value was encrypted for</param>
    /// <param name="result">The span to receive the decrypted plaintext characters</param>
    /// <returns>Number of chars written to result</returns>
    /// <exception cref="ArgumentException">secretIdentifier is empty</exception>
    public int Decrypt(ReadOnlySpan<char> encrypted, ReadOnlySpan<char> secretIdentifier, Span<char> result);

    /// <summary>
    /// An upper bound on how many chars Decrypt will write for the given formatted value.
    /// </summary>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted);

    /// <summary>
    /// The key, base64-encoded, for handing to the native platform's wrap process at the end of
    /// the pipeline. The span points into a buffer the protector owns and zeroes on Dispose:
    /// consume it before disposing, and never copy it into a string. Pass it to the wrap tool on
    /// standard input (<c>--dek-stdin</c>), never as a command-line argument or environment
    /// variable, which process listings and logs capture.
    /// </summary>
    public ReadOnlySpan<char> GetKeyAsBase64();
}
