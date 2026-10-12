using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey.Protector;

/// <summary>
/// Default IDataProtector. Internal: only KeyRing (KeyRing.CreateProtector) can construct one, so
/// callers only ever see it as an IDataProtector - guaranteeing every instance is actually bound
/// to a real KeyRing rather than constructed loose. name is UTF8-encoded once into _aad and used
/// for every Encrypt/Decrypt, so a value protected under one name/purpose fails to decrypt under
/// another. Encrypt resolves keyRing.GetCurrent() fresh on every call rather than capturing a
/// version once at construction, so it always protects new data with whatever the ring's latest
/// rotation is; Decrypt instead resolves whichever version the formatted ciphertext itself
/// names, so old versions stay readable regardless.
/// </summary>
internal sealed class DataProtector(
    string name,
    KeyRing keyRing,
    IEncryptedFormatProvider formatProvider) : IDataProtector
{
    // Strict: an unpaired surrogate throws (an ArgumentException, from KeyRing.CreateProtector)
    // rather than encoding as U+FFFD, which would give two different names the same AAD.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly byte[] _aad = StrictUtf8.GetBytes(name);

    /// <inheritdoc/>
    public string Encrypt(ReadOnlySpan<char> plaintext)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.ProtectorEncrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.ProtectorEncrypt,
                (AttributeNames.Name, name), (AttributeNames.PlaintextLength, plaintext.Length));

        try
        {
            var (version, key) = keyRing.GetCurrent();

            // On the stack, or pinned when too large: never somewhere the GC can copy it.
            var byteCount = Encoding.UTF8.GetByteCount(plaintext);
            Span<byte> plaintextBytes = byteCount <= ArrayUtility.MaxStackBytes
                ? stackalloc byte[byteCount]
                : ArrayUtility.AllocatePinned<byte>(byteCount);
            byte[] encryptedBytes;
            try
            {
                Encoding.UTF8.GetBytes(plaintext, plaintextBytes);
                encryptedBytes = key.Encrypt(plaintextBytes, _aad);
            }
            finally
            {
                ArrayUtility.ZeroMemory(plaintextBytes);
            }

            return formatProvider.Format(new KeyTrackingValue
            {
                KeyVersion = version,
                Value = encryptedBytes
            });
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<char> encrypted, Span<char> result)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.ProtectorDecrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.ProtectorDecrypt,
                (AttributeNames.Name, name), (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            var value = formatProvider.Parse(encrypted);
            var key = keyRing.Get(value.KeyVersion);

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // value.Value.Length is a safe upper bound for the decrypted UTF8 byte count. On the
            // stack, or pinned when too large: never somewhere the GC can copy it.
            Span<byte> plaintextBytes = value.Value.Length <= ArrayUtility.MaxStackBytes
                ? stackalloc byte[value.Value.Length]
                : ArrayUtility.AllocatePinned<byte>(value.Value.Length);
            try
            {
                var bytesWritten = key.Decrypt(value.Value, _aad, plaintextBytes);
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
        => formatProvider.GetMaxDecryptedLength(encrypted);
}
