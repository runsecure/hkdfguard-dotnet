using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <summary>
/// AES-256-GCM IPipelineDataProtector: generates a random 32-byte key in memory at construction
/// and drives a single AesGcmCryptoSession around it for its whole lifetime - no key wrapper, no
/// KeyRing, no refresh. Each Encrypt/Decrypt binds the secret identifier as AAD (via
/// ProtectedConfigurationPurpose); output is formatted via the supplied IEncryptedFormatProvider
/// and tagged with <c>keyVersion</c>. Dispose releases the
/// session and zeroes the key and its base64 form; any use afterwards throws
/// ObjectDisposedException.
/// </summary>
public sealed class AesGcmPipelineDataProtector : IPipelineDataProtector
{
    private const int KeyLength = 32;

    private readonly IEncryptedFormatProvider _formatProvider;
    private readonly int _keyVersion;
    private readonly Lock _gate = new();
    private readonly byte[] _key;
    private readonly EncryptionBudget _budget;
    private char[]? _base64;
    private AesGcmCryptoSession? _session;

    /// <param name="formatProvider">Formats/parses the protected values, e.g. DefaultFormatProvider.</param>
    /// <param name="keyVersion">The version stamped on every value - the version this key will be
    /// registered under once wrapped.</param>
    public AesGcmPipelineDataProtector(IEncryptedFormatProvider formatProvider, int keyVersion)
        : this(formatProvider, keyVersion, NewPinnedKey())
    {
    }

    // Pinned: the key lives for the protector's whole lifetime; a movable array could leave
    // unzeroed copies behind when the GC compacts.
    private static byte[] NewPinnedKey()
    {
        var key = ArrayUtility.AllocatePinned<byte>(KeyLength);
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>The key array, for tests to check it is pinned and zeroed.</summary>
    internal byte[] Key => _key;

    /// <summary>The base64 key buffer once GetKeyAsBase64 has run, for tests to check it is pinned and zeroed.</summary>
    internal char[]? Base64Buffer => _base64;

    /// <param name="key">The 32-byte key - ownership transfers to this instance, which zeroes it on Dispose.</param>
    internal AesGcmPipelineDataProtector(IEncryptedFormatProvider formatProvider, int keyVersion, byte[] key)
        : this(formatProvider, keyVersion, key, new EncryptionBudget())
    {
    }

    internal AesGcmPipelineDataProtector(IEncryptedFormatProvider formatProvider, int keyVersion, byte[] key, EncryptionBudget budget)
    {
        ArgumentNullException.ThrowIfNull(formatProvider);

        _formatProvider = formatProvider;
        _keyVersion = keyVersion;
        _session = new AesGcmCryptoSession(key, budget);
        _key = key;
        _budget = budget;
    }

    /// <inheritdoc/>
    public int KeyVersion => _keyVersion;

    /// <summary>Encryptions performed under this key so far - see <see cref="AesGcmCryptoProvider.MaxEncryptionsPerKey"/>.</summary>
    public long EncryptionCount => _budget.Count;

    /// <inheritdoc/>
    /// <remarks>Encoded once, then the same buffer is returned on every call.</remarks>
    /// <exception cref="ObjectDisposedException">This instance has been disposed</exception>
    public ReadOnlySpan<char> GetKeyAsBase64()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_session is null, this);

            if (_base64 is null)
            {
                // The key in text form, held until Dispose: pinned for the same reason as the key.
                var base64 = ArrayUtility.AllocatePinned<char>(((_key.Length + 2) / 3) * 4);
                Convert.TryToBase64Chars(_key, base64, out _);
                _base64 = base64;
            }

            return _base64;
        }
    }

    /// <inheritdoc/>
    public string Encrypt(ReadOnlySpan<char> plaintext, ReadOnlySpan<char> secretIdentifier)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.ProtectorEncrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.ProtectorEncrypt,
                (AttributeNames.Name, secretIdentifier.ToString()), (AttributeNames.PlaintextLength, plaintext.Length));

        try
        {
            var session = Session;
            var aad = ProtectedConfigurationPurpose.AadFor(secretIdentifier);
            // On the stack, or pinned when too large: never somewhere the GC can copy it.
            var byteCount = Encoding.UTF8.GetByteCount(plaintext);
            Span<byte> plaintextBytes = byteCount <= ArrayUtility.MaxStackBytes
                ? stackalloc byte[byteCount]
                : ArrayUtility.AllocatePinned<byte>(byteCount);
            try
            {
                Encoding.UTF8.GetBytes(plaintext, plaintextBytes);
                var ciphertext = new byte[AesGcmCryptoSession.NonceSize + plaintextBytes.Length + AesGcmCryptoSession.TagSize];
                session.Encrypt(plaintextBytes, aad, ciphertext);

                return _formatProvider.Format(new KeyTrackingValue
                {
                    KeyVersion = _keyVersion,
                    Value = ciphertext
                });
            }
            finally
            {
                ArrayUtility.ZeroMemory(plaintextBytes);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="KeyNotFoundException">The value was protected under a different key version</exception>
    public int Decrypt(ReadOnlySpan<char> encrypted, ReadOnlySpan<char> secretIdentifier, Span<char> result)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.ProtectorDecrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.ProtectorDecrypt,
                (AttributeNames.Name, secretIdentifier.ToString()), (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            var session = Session;
            var aad = ProtectedConfigurationPurpose.AadFor(secretIdentifier);
            var value = _formatProvider.Parse(encrypted);
            if (value.KeyVersion != _keyVersion)
                throw new KeyNotFoundException($"No key is registered for version {value.KeyVersion}.");

            // AEAD ciphertext is always longer than the plaintext it encloses. On the stack, or
            // pinned when too large: never somewhere the GC can copy it.
            Span<byte> plaintextBytes = value.Value.Length <= ArrayUtility.MaxStackBytes
                ? stackalloc byte[value.Value.Length]
                : ArrayUtility.AllocatePinned<byte>(value.Value.Length);
            try
            {
                var bytesWritten = session.Decrypt(value.Value, aad, plaintextBytes);
                return Encoding.UTF8.GetChars(plaintextBytes[..bytesWritten], result);
            }
            finally
            {
                ArrayUtility.ZeroMemory(plaintextBytes);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
        => _formatProvider.GetMaxDecryptedLength(encrypted);

    private AesGcmCryptoSession Session
    {
        get
        {
            var session = _session;
            ObjectDisposedException.ThrowIf(session is null, this);
            return session;
        }
    }

    /// <summary>
    /// Releases the session, zeroing the key, and zeroes its base64 form. Safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            var session = Interlocked.Exchange(ref _session, null);
            if (session is null)
                return;

            session.Dispose();
            if (_base64 is not null)
                ArrayUtility.ZeroMemory(_base64);
        }
    }
}
