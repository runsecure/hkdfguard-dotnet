using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using HkdfGuard.SecureFile;

namespace HkdfGuard.Cache;

/// <summary>
/// An IProtectedReadOnlyCache over a folder on the local filesystem holding one file per secret:
/// the file named name holds that secret's value, already encrypted under the key ring and
/// formatted (enc::v{version}::{base64}). Nothing is read up front: the first lookup of a name
/// reads that one file, authenticates its value, and caches it - still encrypted, exactly as the
/// file holds it - so every later lookup is served from memory without touching the disk.
/// Surrounding whitespace in a file, such as a trailing newline, is ignored.
/// <para>
/// <b>Every file is read through TrustedFile.</b> It is refused - with an
/// UnauthorizedAccessException, and not cached - unless it and every folder above it are owned,
/// and modifiable, only by the operating system's administrators and the principals the
/// <see cref="KeyFileTrust"/> adds, with no untrusted symbolic link on the way. Add the account
/// that deploys secrets, never the one the application runs as.
/// </para>
/// <para>
/// <b>Every value is bound to its name.</b> A file's value must be encrypted with the purpose
/// ProtectedConfigurationPurpose.For(name) - as AesGcmPipelineDataProtector.Encrypt(value, name),
/// or ring.CreateProtector(ProtectedConfigurationPurpose.For(name)), writes it - and a file copied
/// under any other name fails authentication with a CryptographicException when it is loaded,
/// rather than decrypting as that name's value. A file that fails is not cached, so it is read
/// again on the next lookup.
/// </para>
/// <para>
/// A name is a file name: 1-<see cref="MaxNameLength"/> ASCII letters, digits, '-', '_' and '.',
/// not starting with '.' (see <see cref="IsValidName"/>), so it can never reach outside the folder.
/// Any other name, a missing file, a missing folder and an empty file are all reported missing -
/// Decrypt returns 0 - so the cache can sit in a ProtectedCacheCollection beside sources with
/// other naming rules. A missing secret isn't remembered: its file is looked for again on the next
/// lookup. Names are matched exactly, and files are found as the filesystem finds them: exactly on
/// Linux, ignoring case on Windows and, by default, macOS. A file longer than
/// <see cref="MaxFileLength"/> bytes is refused with an InvalidDataException, reading no more than
/// one byte past that; any other failure to read it propagates, and nothing is cached. A lookup
/// made through Decrypt or TryGetMaxDecryptedLength blocks while a file is loaded.
/// </para>
/// <para>
/// A cached value is kept for the life of the instance: a file changed after its secret was loaded
/// is picked up by a new cache instance. Each value decrypts with the key version it names, so it
/// keeps decrypting after a key rotation for as long as the ring holds that version.
/// </para>
/// <para>
/// Telemetry: each file load is a <see cref="ActivityNames.Cache.Populate"/> activity on
/// HkdfGuardTelemetry.Cache, counted in CacheMetrics.Operations as "success", "not_found" or
/// "error"; with sensitive logging on, the secret's name (never a value) is logged.
/// </para>
/// </summary>
public sealed class FilePerSecretCache : IProtectedReadOnlyCache
{
    /// <summary>The longest name a secret's file can have.</summary>
    public const int MaxNameLength = 255;

    /// <summary>The longest file, in bytes, that is read: room for a formatted secret of about 48 KB.</summary>
    public const int MaxFileLength = 64 * 1024;

    private readonly KeyFileTrust _trust;
    private readonly IKeyRing _keyRing;
    private readonly IEncryptedFormatProvider _formatProvider;

    // Each loaded secret's value as its file held it: encrypted, bound to its name. Exact names,
    // since each spelling is bound - and authenticated - separately.
    private readonly ConcurrentDictionary<string, KeyTrackingValue> _values = new(StringComparer.Ordinal);

    /// <param name="folderPath">The folder holding one file per secret, absolute or relative to the
    /// working directory.</param>
    /// <param name="trust">Who besides administrators is trusted to have written the folder and
    /// its files; <see cref="KeyFileTrust.AdministratorsOnly"/> for no one.</param>
    /// <param name="keyRing">Supplies the key each file's value names. Owned by the caller: the
    /// cache never disposes keys.</param>
    /// <param name="formatProvider">Parses each file's formatted value - the same format the
    /// values were written in.</param>
    /// <exception cref="ArgumentException">folderPath is empty</exception>
    /// <exception cref="ArgumentNullException">folderPath, trust, keyRing or formatProvider is null</exception>
    /// <exception cref="DirectoryNotFoundException">folderPath doesn't name an existing folder</exception>
    public FilePerSecretCache(string folderPath, KeyFileTrust trust, IKeyRing keyRing, IEncryptedFormatProvider formatProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(folderPath);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(formatProvider);

        FolderPath = Path.GetFullPath(folderPath);
        if (!Directory.Exists(FolderPath))
            throw new DirectoryNotFoundException($"The secrets folder '{FolderPath}' doesn't exist.");

        _trust = trust;
        _keyRing = keyRing;
        _formatProvider = formatProvider;
    }

    /// <summary>The full path of the folder the secrets' files are read from.</summary>
    public string FolderPath { get; }

    /// <summary>Whether name can be a secret's file name: 1-<see cref="MaxNameLength"/> ASCII
    /// letters, digits, '-', '_' and '.', not starting with '.'.</summary>
    public static bool IsValidName(string? name)
        => !string.IsNullOrEmpty(name)
           && name.Length <= MaxNameLength
           && name[0] != '.'
           && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">The value's key version is no longer in the ring</exception>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            return GetValue(name) is { } value ? DecryptValue(name, value, result) : 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">The value's key version is no longer in the ring</exception>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            return GetValue(name) is { } value ? DecryptValue(name, value, result) : 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        var value = GetValue(name);
        maxLength = value?.Value.Length ?? 0;
        return value is not null;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">The value's key version is no longer in the ring</exception>
    public async ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            return await GetValueAsync(name, cancellationToken).ConfigureAwait(false) is { } value
                ? DecryptValue(name, value, result.Span)
                : 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">The value's key version is no longer in the ring</exception>
    public async ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
    {
        using var activity = StartDecryptActivity(name);
        try
        {
            return await GetValueAsync(name, cancellationToken).ConfigureAwait(false) is { } value
                ? DecryptValue(name, value, result.Span)
                : 0;
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">The file's value wasn't encrypted for this name, or was altered</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    public async ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
        => (await GetValueAsync(name, cancellationToken).ConfigureAwait(false))?.Value.Length ?? 0;

    private static System.Diagnostics.Activity? StartDecryptActivity(string name)
    {
        var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));
        return activity;
    }

    private int DecryptValue(string name, KeyTrackingValue value, Span<byte> result)
        => _keyRing.Get(value.KeyVersion).Decrypt(value.Value, ProtectedConfigurationPurpose.AadFor(name), result);

    private int DecryptValue(string name, KeyTrackingValue value, Span<char> result)
    {
        // AEAD ciphertext is always at least as long as the plaintext it encloses, so
        // value.Value.Length is a safe upper bound for the decrypted UTF8 byte count. On the
        // stack, or pinned when too large: never somewhere the GC can copy it.
        Span<byte> plaintextBytes = value.Value.Length <= ArrayUtility.MaxStackBytes
            ? stackalloc byte[value.Value.Length]
            : ArrayUtility.AllocatePinned<byte>(value.Value.Length);
        try
        {
            var bytesWritten = DecryptValue(name, value, plaintextBytes);
            return Encoding.UTF8.GetChars(plaintextBytes[..bytesWritten], result);
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintextBytes);
        }
    }

    // Blocks while a file is loaded; TrustedFile reads only asynchronously.
    private KeyTrackingValue? GetValue(string name)
        => GetValueAsync(name, CancellationToken.None).AsTask().GetAwaiter().GetResult();

    // The cached value for name, loading it from its file on a miss; null if name can't be a file
    // name or there is no value. Concurrent misses may each load the file; the first stored is kept.
    private async ValueTask<KeyTrackingValue?> GetValueAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (_values.TryGetValue(name, out var cached))
            return cached;

        cancellationToken.ThrowIfCancellationRequested();
        if (!IsValidName(name))
            return null;

        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Populate);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Populate, (AttributeNames.Name, name));

        try
        {
            if (await ReadAsync(name, cancellationToken).ConfigureAwait(false) is not { } encrypted)
            {
                RecordOperation("not_found");
                return null;
            }

            var value = _formatProvider.Parse(encrypted);
            Authenticate(name, value);
            RecordOperation("success");
            return _values.GetOrAdd(name, value);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            RecordOperation("error");
            throw;
        }
    }

    // Decrypts value once into a buffer that is zeroed at once, so only a value that authenticates
    // under name - and a key version the ring holds - is ever cached.
    private void Authenticate(string name, KeyTrackingValue value)
    {
        Span<byte> plaintext = value.Value.Length <= ArrayUtility.MaxStackBytes
            ? stackalloc byte[value.Value.Length]
            : ArrayUtility.AllocatePinned<byte>(value.Value.Length);
        try
        {
            DecryptValue(name, value, plaintext);
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    // The secret's formatted value from its trusted file, trimmed; null if the file or folder
    // doesn't exist, or the file is empty.
    private async ValueTask<string?> ReadAsync(string name, CancellationToken cancellationToken)
    {
        byte[] contents;
        try
        {
            contents = await TrustedFile.ReadAsync(Path.Join(FolderPath, name), _trust, MaxFileLength, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        var encrypted = Encoding.UTF8.GetString(contents).Trim();
        return encrypted.Length == 0 ? null : encrypted;
    }

    private static void RecordOperation(string result)
        => CacheMetrics.Operations.Add(1,
            new KeyValuePair<string, object?>(AttributeNames.OperationName, ActivityNames.Cache.Populate),
            new KeyValuePair<string, object?>(AttributeNames.Result, result));
}
