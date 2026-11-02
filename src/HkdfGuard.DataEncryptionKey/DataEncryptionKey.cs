using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataEncryptionKey backed by an ICryptoProvider, which owns the actual key material - how it
/// is revealed and refreshed - and performs the AEAD encrypt/decrypt. This class sizes the output
/// buffer via the provider, trims the result to exactly what was written, and records telemetry
/// for every operation. Owns its provider: Dispose disposes it (stopping any background refresh
/// and zeroing its key).
/// <para>
/// A key given an <see cref="EncryptionDeadline"/> stops encrypting once the deadline passes -
/// Encrypt then throws EncryptionLimitReachedException - while Decrypt keeps working. KeyRingBuilder
/// gives every key-file key one, from the file's age (see KeyRingBuilder.WithKeyFileMaxAgeDays).
/// </para>
/// </summary>
public sealed class DataEncryptionKey : IDataEncryptionKey, IDisposable, IAsyncDisposable
{
    private readonly ICryptoProvider _provider;
    private readonly TimeProvider _timeProvider;
    private int _disposed;
    private int _warned;
    private int _expired;

    /// <summary>A key that encrypts without a time limit.</summary>
    public DataEncryptionKey(ICryptoProvider provider)
        : this(provider, null)
    {
    }

    /// <summary>A key that stops encrypting at <paramref name="deadline"/>.</summary>
    /// <param name="provider">Owns the key material and performs the AEAD</param>
    /// <param name="deadline">When this key stops encrypting; it encrypts without a time limit when null</param>
    public DataEncryptionKey(ICryptoProvider provider, EncryptionDeadline? deadline)
        : this(provider, deadline, TimeProvider.System)
    {
    }

    // Tests and KeyRingBuilder: the clock the deadline is checked against.
    internal DataEncryptionKey(ICryptoProvider provider, EncryptionDeadline? deadline, TimeProvider timeProvider)
    {
        _provider = provider;
        Deadline = deadline;
        _timeProvider = timeProvider;
    }

    /// <summary>When this key stops encrypting; null when it encrypts without a time limit.</summary>
    public EncryptionDeadline? Deadline { get; }

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty);

    /// <inheritdoc/>
    /// <exception cref="EncryptionLimitReachedException">The key has passed its deadline; it must be rotated, and decryption still works.</exception>
    public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyEncrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyEncrypt,
                (AttributeNames.PlaintextLength, plaintext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            if (CheckDeadline())
            {
                ArrayUtility.ZeroMemory(plaintext); // the provider never sees it, so honor the contract here
                throw new EncryptionLimitReachedException(Deadline!.Reason);
            }

            var buffer = new byte[_provider.GetEncryptedAllocationLength(plaintext.Length)];
            var written = _provider.Encrypt(plaintext, aad, buffer);

            // Providers that size exactly (e.g. AES-GCM) need no trim copy; others may over-allocate.
            return written == buffer.Length ? buffer : buffer[..written];
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>
    /// Checks the deadline against the clock, announcing a warning or expiry the first time each is
    /// reached; returns whether this key has stopped encrypting. Each callback runs at most once,
    /// even under concurrent encrypts, and one that throws is ignored, so a faulty logger never
    /// decides whether a value is encrypted. Also called by KeyRingBuilder.BuildAsync, so a current
    /// key file nearing or past its age is reported at startup.
    /// </summary>
    internal bool CheckDeadline() => CheckDeadline(_timeProvider.GetUtcNow());

    /// <inheritdoc cref="CheckDeadline()"/>
    internal bool CheckDeadline(DateTimeOffset now)
    {
        var deadline = Deadline;
        if (deadline is null)
            return false;

        if (now >= deadline.RefuseAt)
        {
            if (Interlocked.Exchange(ref _expired, 1) == 0)
            {
                // A warning not yet announced never is: the expiry supersedes it.
                Volatile.Write(ref _warned, 1);
                Quietly(deadline.OnExpired);
            }

            return true;
        }

        if (now >= deadline.WarnAt && Interlocked.Exchange(ref _warned, 1) == 0)
            Quietly(deadline.OnWarning);

        return false;
    }

    private static void Quietly(Action? callback)
    {
        try
        {
            callback?.Invoke();
        }
        catch
        {
            // See CheckDeadline: a throwing callback never decides whether a value is encrypted.
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    /// <remarks>Never limited by the deadline.</remarks>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyDecrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyDecrypt,
                (AttributeNames.CiphertextLength, ciphertext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            return _provider.Decrypt(ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>Disposes the underlying provider, awaiting its shutdown. Safe to call more than once.</summary>
    public ValueTask DisposeAsync()
        => Interlocked.Exchange(ref _disposed, 1) == 0 ? _provider.DisposeAsync() : ValueTask.CompletedTask;

    /// <summary>Disposes the underlying provider. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            _provider.Dispose();
    }
}
