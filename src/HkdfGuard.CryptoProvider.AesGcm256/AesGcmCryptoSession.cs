using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.CryptoProvider.AesGcm256;

/// <summary>
/// An AES-256-GCM cipher bound to a single 32-byte key, supplied once at construction. This
/// instance is meant to be held for a while - by AesGcmCryptoProvider until its next background
/// refresh, or by AesGcmPipelineDataProtector for its whole lifetime - and Disposed (releasing
/// every AesGcm instance and zeroing the key) once no longer needed rather than rebuilt per
/// operation.
/// <para>
/// Thread-safe. <see cref="AesGcm"/> itself is not: on the OpenSSL backend (Linux) one instance
/// owns a single cipher context that every call mutates - the nonce is set, then the data run
/// through it - so two threads sharing an instance can encrypt one plaintext under the other's
/// nonce, a nonce reuse that breaks GCM. Every Encrypt/Decrypt here therefore takes an
/// <see cref="AesGcm"/> for its exclusive use from a small per-session pool and returns it after.
/// The pool grows to the peak number of concurrent operations and no further; each pooled instance
/// holds its own copy of the key in native crypto state, all released on Dispose.
/// </para>
/// </summary>
internal class AesGcmCryptoSession : IDisposable
{
    internal const int TagSize = 16;
    internal const int NonceSize = 12;
    private const int KeyLength = 32;

    private readonly byte[] _key;
    private readonly EncryptionBudget _budget;
    // Instances not currently in use by an operation. Rent pops one (or builds one if empty),
    // Return pushes it back - so an instance is only ever touched by one thread at a time.
    private readonly ConcurrentStack<AesGcm> _idle = new();
    // Serializes building a new AesGcm from _key against Dispose zeroing _key.
    private readonly Lock _gate = new();
    private int _instanceCount;
    private volatile bool _disposed;

    /// <param name="key">The 32-byte AES-256 key this session encrypts/decrypts with - ownership
    /// transfers to this instance, which zeroes it on Dispose.</param>
    /// <exception cref="ArgumentException">key is empty/all-zero, or not exactly 32 bytes</exception>
    internal AesGcmCryptoSession(byte[] key)
        : this(key, new EncryptionBudget())
    {
    }

    /// <param name="key">See the single-argument constructor.</param>
    /// <param name="budget">The encryption count for this key - shared across every session built
    /// on the same key, since the nonce-reuse limit applies to the key, not the session.</param>
    internal AesGcmCryptoSession(byte[] key, EncryptionBudget budget)
    {
        _budget = budget;

        if (ArrayUtility.IsNullOrEmpty(key))
            throw new ArgumentException("AES key must not be empty or all zero.", nameof(key));

        if (key.Length != KeyLength)
            throw new ArgumentException($"AES key must be exactly {KeyLength} bytes.", nameof(key));

        _key = key;

        // Build the first instance eagerly so a bad key fails here, and the first operation
        // never takes the construction lock.
        _idle.Push(new AesGcm(key, TagSize));
        _instanceCount = 1;
    }

    /// <summary>How many AesGcm instances this session has built so far - the peak concurrency it has seen.</summary>
    /// <summary>The key array, for tests to check it is pinned and zeroed.</summary>
    internal byte[] Key => _key;

    internal int InstanceCount => Volatile.Read(ref _instanceCount);

    /// <summary>How many AesGcm instances are pooled and not in use by an operation right now.</summary>
    internal int IdleInstanceCount => _idle.Count;

    internal int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    internal int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.CryptoProviderAesGcm256.ActivitySource.StartActivity(ActivityNames.CryptoProviderAesGcm256.Encrypt);
        if (HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging)
            HkdfGuardTelemetry.CryptoProviderAesGcm256.LogSensitiveOperation(activity, ActivityNames.CryptoProviderAesGcm256.Encrypt,
                (AttributeNames.PlaintextLength, plaintext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            if (_budget.Consume())
                activity?.AddEvent(new ActivityEvent(EventNames.EncryptionBudgetWarning, tags: new ActivityTagsCollection
                {
                    [AttributeNames.EncryptionCount] = _budget.Count,
                    [AttributeNames.EncryptionLimit] = _budget.Limit,
                }));

            var aes = Rent();
            try
            {
                return CoreEncrypt(aes, plaintext, aad, result);
            }
            finally
            {
                Return(aes);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    private static int CoreEncrypt(AesGcm aes, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (result.Length < NonceSize + plaintext.Length + TagSize)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        // Layout: [nonce | ciphertext | tag]
        var nonce = result[..NonceSize];
        var ciphertext = result.Slice(NonceSize, plaintext.Length);
        var tag = result.Slice(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return NonceSize + plaintext.Length + TagSize;
    }

    internal int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    internal int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.CryptoProviderAesGcm256.ActivitySource.StartActivity(ActivityNames.CryptoProviderAesGcm256.Decrypt);
        if (HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging)
            HkdfGuardTelemetry.CryptoProviderAesGcm256.LogSensitiveOperation(activity, ActivityNames.CryptoProviderAesGcm256.Decrypt,
                (AttributeNames.CiphertextLength, ciphertext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            var aes = Rent();
            try
            {
                return CoreDecrypt(aes, ciphertext, aad, result);
            }
            finally
            {
                Return(aes);
            }
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    private static int CoreDecrypt(AesGcm aes, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ciphertext.Length < NonceSize + TagSize)
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

        var resultLength = ciphertext.Length - NonceSize - TagSize;

        if (result.Length < resultLength)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        var nonce = ciphertext[..NonceSize];
        var ct = ciphertext.Slice(NonceSize, resultLength);
        var tag = ciphertext.Slice(NonceSize + resultLength, TagSize);

        aes.Decrypt(nonce, ct, tag, result[..resultLength], aad);

        return resultLength;
    }

    /// <summary>
    /// Takes an AesGcm for the calling operation's exclusive use: an idle one if there is one,
    /// otherwise a new one built from the key. Pair with <see cref="Return"/>.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This session has been disposed</exception>
    internal AesGcm Rent()
    {
        if (_idle.TryPop(out var aes))
            return aes;

        lock (_gate)
        {
            // Dispose drains the pool and zeroes the key under this same lock, so a session that
            // is disposed can't hand out an instance built from a zeroed key.
            ObjectDisposedException.ThrowIf(_disposed, this);
            Interlocked.Increment(ref _instanceCount);
            return new AesGcm(_key, TagSize);
        }
    }

    /// <summary>
    /// Gives an instance taken by <see cref="Rent"/> back to the pool. If the session was disposed
    /// in the meantime the instance is released instead of pooled.
    /// </summary>
    internal void Return(AesGcm aes)
    {
        _idle.Push(aes);

        // Dispose may have drained the pool before this push landed; if so, drain it again so no
        // instance (and its copy of the key) outlives the session.
        if (_disposed)
            DrainIdle();
    }

    private void DrainIdle()
    {
        while (_idle.TryPop(out var aes))
            aes.Dispose();
    }

    /// <summary>
    /// Releases every pooled AesGcm instance and zeroes the key. An instance an in-flight
    /// operation holds is released when that operation returns it. Safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;

            _disposed = true;
            DrainIdle();
            CryptographicOperations.ZeroMemory(_key);
        }
    }
}
