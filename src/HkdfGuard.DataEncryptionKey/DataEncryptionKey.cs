using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataEncryptionKey backed by an ICryptoProvider, which owns the actual key material - how it
/// is revealed and refreshed - and performs the AEAD encrypt/decrypt. This class sizes the output
/// buffer via the provider, trims the result to exactly what was written, and records telemetry
/// for every operation. Owns its provider: Dispose disposes it (stopping any background refresh
/// and zeroing its key).
/// </summary>
public sealed class DataEncryptionKey(ICryptoProvider provider) : IDataEncryptionKey, IDisposable, IAsyncDisposable
{
    private int _disposed;

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty);

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyEncrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyEncrypt,
                (AttributeNames.PlaintextLength, plaintext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            var buffer = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
            var written = provider.Encrypt(plaintext, aad, buffer);

            // Providers that size exactly (e.g. AES-GCM) need no trim copy; others may over-allocate.
            return written == buffer.Length ? buffer : buffer[..written];
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyDecrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyDecrypt,
                (AttributeNames.CiphertextLength, ciphertext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            return provider.Decrypt(ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>Disposes the underlying provider, awaiting its shutdown. Safe to call more than once.</summary>
    public ValueTask DisposeAsync()
        => Interlocked.Exchange(ref _disposed, 1) == 0 ? provider.DisposeAsync() : ValueTask.CompletedTask;

    /// <summary>Disposes the underlying provider. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            provider.Dispose();
    }
}
