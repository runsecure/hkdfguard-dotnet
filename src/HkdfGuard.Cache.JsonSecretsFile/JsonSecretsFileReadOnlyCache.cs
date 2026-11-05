using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using HkdfGuard.SecureFile;

namespace HkdfGuard.Cache.JsonSecretsFile;

/// <summary>
/// An IProtectedReadOnlyCache over one JSON file holding every secret, as a pipeline's
/// ISecretPipelineWriter.WriteJsonSecrets writes it: a single object whose members map each
/// secret's name to its value, already encrypted under the key ring and formatted
/// (enc::v{version}::{base64}). Nothing is read up front: the first lookup reads the whole file,
/// authenticates every value in it, and keeps them - still encrypted, exactly as the file holds
/// them - so every later lookup is served from memory without touching the disk.
/// <para>
/// <b>The file is read through TrustedFile.</b> It is refused - with an
/// UnauthorizedAccessException, and nothing kept - unless it and every folder above it are owned,
/// and modifiable, only by the operating system's administrators and the principals the
/// <see cref="KeyFileTrust"/> adds, with no untrusted symbolic link on the way. Add the account
/// that deploys secrets, never the one the application runs as.
/// </para>
/// <para>
/// <b>Every value is bound to its name.</b> A member's value must be encrypted with the purpose
/// ProtectedConfigurationPurpose.For(name) - as AesGcmPipelineDataProtector.Encrypt(value, name)
/// writes it - and a value moved under any other name fails authentication. The file is delivered
/// as one, so it is loaded as one: a value that fails authentication, or names a key version the
/// ring doesn't hold, fails the whole load with a CryptographicException or KeyNotFoundException,
/// and nothing is kept, so the file is read again on the next lookup.
/// </para>
/// <para>
/// <b>The file must be exactly that object</b> - one member per secret, each name a valid
/// FilePerSecretCache name (<see cref="FilePerSecretCache.IsValidName"/>), no name twice ignoring
/// case, each value a non-empty string - or it is refused with an InvalidDataException. Names are
/// looked up ignoring ASCII case, as the values are bound; any name that couldn't be one is
/// reported missing - Decrypt returns 0 - so the cache can sit in a ProtectedCacheCollection
/// beside sources with other naming rules. A missing file reports every secret missing, and isn't
/// remembered: it is looked for again on the next lookup. A file longer than the maximum given is
/// refused with an InvalidDataException, reading no more than one byte past it; any other failure
/// to read it propagates. A lookup made through Decrypt or TryGetMaxDecryptedLength blocks while
/// the file is loaded.
/// </para>
/// <para>
/// The values loaded are kept for the life of the instance: a file changed after it was loaded is
/// picked up by a new cache instance. Each value decrypts with the key version it names, so it
/// keeps decrypting after a key rotation for as long as the ring holds that version.
/// </para>
/// <para>
/// Telemetry: each load of the file is a <see cref="ActivityNames.Cache.Populate"/> activity on
/// HkdfGuardTelemetry.Cache, counted in CacheMetrics.Operations as "success", "not_found" or
/// "error"; with sensitive logging on, the file's path and each looked-up name (never a value) are
/// logged.
/// </para>
/// </summary>
public sealed class JsonSecretsFileReadOnlyCache : IProtectedReadOnlyCache
{
    /// <summary>The longest file read by default, in bytes: room for hundreds of formatted secrets.</summary>
    public const int DefaultMaxFileLength = 1024 * 1024;

    private readonly KeyFileTrust _trust;
    private readonly IKeyRing _keyRing;
    private readonly IEncryptedFormatProvider _formatProvider;
    private readonly int _maxFileLength;

    // One load at a time; once a load succeeds, its values are kept and the gate is never needed again.
    private readonly SemaphoreSlim _loading = new(1, 1);
    private volatile FrozenDictionary<string, KeyTrackingValue>? _values;

    /// <param name="filePath">The JSON file holding the secrets, absolute or relative to the working directory.</param>
    /// <param name="trust">Who besides administrators is trusted to have written the file and the
    /// folders above it; <see cref="KeyFileTrust.AdministratorsOnly"/> for no one.</param>
    /// <param name="keyRing">Supplies the key each value names. Owned by the caller: the cache
    /// never disposes keys.</param>
    /// <param name="formatProvider">Parses each formatted value - the same format the values were written in.</param>
    /// <param name="maxFileLength">The longest file read, in bytes; the read buffer is this large,
    /// so keep it close to the largest file expected.</param>
    /// <exception cref="ArgumentException">filePath is empty</exception>
    /// <exception cref="ArgumentNullException">filePath, trust, keyRing or formatProvider is null</exception>
    /// <exception cref="ArgumentOutOfRangeException">maxFileLength isn't positive</exception>
    /// <exception cref="FileNotFoundException">filePath doesn't name an existing file</exception>
    public JsonSecretsFileReadOnlyCache(string filePath, KeyFileTrust trust, IKeyRing keyRing, IEncryptedFormatProvider formatProvider,
        int maxFileLength = DefaultMaxFileLength)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(keyRing);
        ArgumentNullException.ThrowIfNull(formatProvider);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFileLength);

        FilePath = Path.GetFullPath(filePath);
        if (!File.Exists(FilePath))
            throw new FileNotFoundException($"The secrets file '{FilePath}' doesn't exist.", FilePath);

        _trust = trust;
        _keyRing = keyRing;
        _formatProvider = formatProvider;
        _maxFileLength = maxFileLength;
    }

    /// <summary>The full path of the JSON file the secrets are read from.</summary>
    public string FilePath { get; }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
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
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
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
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        var value = GetValue(name);
        maxLength = value?.Value.Length ?? 0;
        return value is not null;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
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
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
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
    /// <exception cref="CryptographicException">A value in the file wasn't encrypted for its name, or was altered</exception>
    /// <exception cref="InvalidDataException">The file isn't the secrets object, or is too long</exception>
    /// <exception cref="UnauthorizedAccessException">The file's location isn't trusted, or this account may not read it</exception>
    /// <exception cref="KeyNotFoundException">A value's key version isn't in the ring</exception>
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

    // Blocks while the file is loaded; TrustedFile reads only asynchronously.
    private KeyTrackingValue? GetValue(string name)
        => GetValueAsync(name, CancellationToken.None).AsTask().GetAwaiter().GetResult();

    // name's value, loading the file on the first lookup; null if name couldn't be a secret's name,
    // the file is missing, or it holds no value for name.
    private async ValueTask<KeyTrackingValue?> GetValueAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);
        cancellationToken.ThrowIfCancellationRequested();

        // Checked first: OrdinalIgnoreCase folds some non-ASCII letters onto ASCII ones ('ı' onto
        // 'I'), and names are bound ignoring ASCII case only.
        if (!FilePerSecretCache.IsValidName(name))
            return null;

        var values = _values ?? await LoadAsync(cancellationToken).ConfigureAwait(false);
        return values is not null && values.TryGetValue(name, out var value) ? value : null;
    }

    // Reads, parses and authenticates the whole file, keeping its values once every one passes;
    // null if the file is missing.
    private async ValueTask<FrozenDictionary<string, KeyTrackingValue>?> LoadAsync(CancellationToken cancellationToken)
    {
        await _loading.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Another lookup may have loaded it while this one waited.
            if (_values is { } loaded)
                return loaded;

            using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Populate);
            if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
                HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Populate, (AttributeNames.Name, FilePath));

            try
            {
                if (await ReadAsync(cancellationToken).ConfigureAwait(false) is not { } contents)
                {
                    RecordOperation("not_found");
                    return null;
                }

                var values = Parse(contents);
                foreach (var (name, value) in values)
                    Authenticate(name, value);

                RecordOperation("success");
                return _values = values;
            }
            catch (Exception ex)
            {
                ComponentTelemetry.RecordException(activity, ex);
                RecordOperation("error");
                throw;
            }
        }
        finally
        {
            _loading.Release();
        }
    }

    // The file's contents from TrustedFile; null if the file or a folder above it doesn't exist.
    private async ValueTask<byte[]?> ReadAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await TrustedFile.ReadAsync(FilePath, _trust, _maxFileLength, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    // The secrets object's members, each value parsed but not yet authenticated.
    private FrozenDictionary<string, KeyTrackingValue> Parse(byte[] contents)
    {
        var values = new Dictionary<string, KeyTrackingValue>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var reader = new Utf8JsonReader(contents);
            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
                throw Invalid($"holds a {reader.TokenType}, not an object of secrets");

            // The reader throws on anything malformed or incomplete, so inside the object each token
            // read is a member's name or the object's end, and after a name, its value.
            while (true)
            {
                reader.Read();
                if (reader.TokenType == JsonTokenType.EndObject)
                    break;

                var name = reader.GetString()!;
                if (!FilePerSecretCache.IsValidName(name))
                    throw Invalid($"names a secret '{name}', which isn't a secret's name");

                reader.Read();
                var encrypted = reader.TokenType == JsonTokenType.String ? reader.GetString()!.Trim() : "";
                if (encrypted.Length == 0)
                    throw Invalid($"holds no value for '{name}': each must be a non-empty string");
                if (!values.TryAdd(name, _formatProvider.Parse(encrypted)))
                    throw Invalid($"names '{name}' more than once");
            }

            // Anything after the object - a second value, stray text - throws here.
            reader.Read();
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The secrets file '{FilePath}' isn't valid JSON: {ex.Message}", ex);
        }

        return values.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private InvalidDataException Invalid(string problem) => new($"The secrets file '{FilePath}' {problem}.");

    // Decrypts value once into a buffer that is zeroed at once, so only values that authenticate
    // under their names - and key versions the ring holds - are ever kept.
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

    private static void RecordOperation(string result)
        => CacheMetrics.Operations.Add(1,
            new KeyValuePair<string, object?>(AttributeNames.OperationName, ActivityNames.Cache.Populate),
            new KeyValuePair<string, object?>(AttributeNames.Result, result));
}
