using System.Collections.Concurrent;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache;

/// <summary>How a <see cref="RemoteSecretCache"/> matches names, which must be how its secret store does.</summary>
public enum SecretNameMatching
{
    /// <summary>Names differing only in ASCII case are one secret (e.g. Azure Key Vault).</summary>
    IgnoreAsciiCase,

    /// <summary>
    /// Names are matched exactly; names differing in case are different secrets (e.g. AWS Secrets
    /// Manager, Google Secret Manager). A name holding '!' is reported missing without a fetch -
    /// none of those stores allow it, and it marks case in entry names (see <see cref="RemoteSecretCache"/>).
    /// </summary>
    Exact,
}

/// <summary>
/// The shared plumbing of an IProtectedReadOnlyCache over a remote secret store: nothing is fetched
/// up front; the first Decrypt/TryGetMaxDecryptedLength for a name that isn't cached yet calls
/// <see cref="Fetch"/> for that one secret, encrypts every value it hands over under the ring's
/// current key, and caches the ciphertext; every later lookup is served from the cache. A subclass
/// supplies only <see cref="IsValidName"/> and <see cref="Fetch"/> - one call that reads one secret
/// by name, never a listing.
/// <para>
/// A name is a secret's name, optionally followed by <see cref="KeySeparator"/> and a key:
/// "app-config#api-key" is the api-key key of the secret app-config, which <see cref="Fetch"/>
/// hands over with <see cref="SecretValueSink.SetKeyBytes"/> (or, for a secret holding a JSON
/// object, <see cref="SecretValueSink.SetBytesWithJsonKeys"/>), and "app-config" is the secret's
/// whole value, or its <see cref="DefaultKey"/> where the store has one. One fetch caches the whole
/// value and every key it hands over, so the first lookup of any of them fetches the secret once
/// and the rest are already cached. A key is 1-<see cref="MaxKeyLength"/> printable ASCII
/// characters other than space, '!' and '#' (see <see cref="IsValidKey"/>), and is matched exactly
/// whatever the store's matching.
/// </para>
/// <para>
/// A name whose secret <see cref="IsValidName"/> rejects, or whose key isn't one, is reported
/// missing without a fetch, so a cache can sit in a ProtectedCacheCollection beside sources with
/// other naming rules. A name the fetch hands no value for, or an empty one, is reported missing -
/// Decrypt returns 0 - and isn't remembered, so it is fetched again on the next request (a key a
/// cached secret doesn't hold costs a fetch every time). An exception from <see cref="Fetch"/>
/// propagates to the caller unchanged, and nothing that fetch handed over is cached. Concurrent
/// lookups of the same uncached secret - of any of its keys, synchronous or asynchronous - share one
/// fetch. A cached value is
/// kept for the life of the instance: a later fetch of the same secret adds keys that weren't
/// cached yet, but never replaces one that was.
/// </para>
/// <para>
/// DecryptAsync and GetMaxDecryptedLengthAsync fetch through <see cref="FetchAsync"/>, which a
/// store with an asynchronous client overrides, so a miss doesn't block a thread; Decrypt and
/// TryGetMaxDecryptedLength fetch through <see cref="Fetch"/>, blocking until it returns. A caller
/// cancelling its own lookup cancels the fetch only if it started it; a lookup whose shared fetch
/// was cancelled by the caller that started it starts a new one.
/// </para>
/// <para>
/// Encryption, name binding and key rotation are ProtectedCacheBase's. It matches names ignoring
/// ASCII case, so keys - and, under <see cref="SecretNameMatching.Exact"/>, secret names - are
/// stored there under a case-escaped spelling: every upper-case ASCII letter becomes '!' and its
/// lower-case form, so "prod/Db" and "prod/db" are different entries, each bound to its own spelling.
/// </para>
/// <para>
/// Telemetry: each fetch is a <see cref="ActivityNames.Cache.Populate"/> activity on
/// HkdfGuardTelemetry.Cache, counted in CacheMetrics.Operations as "success", "not_found" or "error";
/// with sensitive logging on, the secret's name (never a value) is logged.
/// </para>
/// </summary>
public abstract class RemoteSecretCache : IProtectedReadOnlyCache
{
    /// <summary>Separates a secret's name from a key it holds: "app-config#api-key".</summary>
    public const char KeySeparator = '#';

    /// <summary>The longest key a name can hold.</summary>
    public const int MaxKeyLength = 256;

    private const char UpperCaseMarker = '!';

    private readonly Store _store;
    private readonly SecretNameMatching _matching;
    private readonly ILogger? _logger;

    /// <param name="keyRing">Supplies the key every fetched secret is encrypted under. Owned by the
    /// caller: the cache never disposes keys.</param>
    /// <param name="matching">How the secret store matches names.</param>
    /// <param name="logger">Optional; receives a debug log per fetched name when sensitive logging is
    /// enabled, and an error log per failed fetch.</param>
    /// <exception cref="ArgumentNullException">keyRing is null</exception>
    protected RemoteSecretCache(IKeyRing keyRing, SecretNameMatching matching, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        _store = new Store(this, keyRing);
        _matching = matching;
        _logger = logger;
    }

    /// <summary>
    /// The key a name without one reads, for a store whose secrets are all sets of keys (HashiCorp
    /// Vault's KV); null - the default - when such a name reads the secret's whole value.
    /// </summary>
    protected virtual string? DefaultKey => null;

    /// <summary>Whether the secret store can hold a secret named name; a name it can't is never fetched.</summary>
    protected abstract bool IsValidName(string name);

    /// <summary>
    /// Reads the one secret named name and hands its current value, and any keys it holds, to
    /// <paramref name="value"/>, or returns without doing so if it doesn't exist. Any other failure
    /// should throw. Called only for a name <see cref="IsValidName"/> accepts, and never while
    /// another fetch of the same secret is running.
    /// </summary>
    protected abstract void Fetch(string name, SecretValueSink value);

    /// <summary>
    /// <see cref="Fetch"/> without blocking, for DecryptAsync and GetMaxDecryptedLengthAsync. The
    /// default implementation calls <see cref="Fetch"/>; a store with an asynchronous client
    /// overrides it. Hand values to the sink between awaits, from memory no await spans.
    /// </summary>
    /// <param name="name">The secret to read, as for <see cref="Fetch"/></param>
    /// <param name="value">Receives what was read</param>
    /// <param name="cancellationToken">Cancels the read</param>
    protected virtual ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Fetch(name, value);
        return ValueTask.CompletedTask;
    }

    /// <summary>Whether key can follow <see cref="KeySeparator"/> in a name: 1-<see cref="MaxKeyLength"/>
    /// printable ASCII characters other than space, '!' and '#'.</summary>
    public static bool IsValidKey(string? key)
        => !string.IsNullOrEmpty(key)
           && key.Length <= MaxKeyLength
           && key.All(c => c is > ' ' and <= '~' and not UpperCaseMarker and not KeySeparator);

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public int Decrypt(string name, Span<byte> result)
        => TryGetEntryName(name, out var entryName) ? _store.Decrypt(entryName, result) : 0;

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public int Decrypt(string name, Span<char> result)
        => TryGetEntryName(name, out var entryName) ? _store.Decrypt(entryName, result) : 0;

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        if (TryGetEntryName(name, out var entryName))
            return _store.TryGetMaxDecryptedLength(entryName, out maxLength);

        maxLength = 0;
        return false;
    }

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public ValueTask<int> DecryptAsync(string name, Memory<byte> result, CancellationToken cancellationToken = default)
        => TryGetEntryName(name, out var entryName) ? _store.DecryptAsync(entryName, result, cancellationToken) : ValueTask.FromResult(0);

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public ValueTask<int> DecryptAsync(string name, Memory<char> result, CancellationToken cancellationToken = default)
        => TryGetEntryName(name, out var entryName) ? _store.DecryptAsync(entryName, result, cancellationToken) : ValueTask.FromResult(0);

    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException">name is null</exception>
    public ValueTask<int> GetMaxDecryptedLengthAsync(string name, CancellationToken cancellationToken = default)
        => TryGetEntryName(name, out var entryName) ? _store.GetMaxDecryptedLengthAsync(entryName, cancellationToken) : ValueTask.FromResult(0);

    /// <summary>
    /// The case-escaped spelling of a name or key: each upper-case ASCII letter becomes '!' and its
    /// lower-case form, so the result holds no upper-case letters and matching it ignoring ASCII case
    /// is matching it exactly. "prod/Db" is "prod/!db"; "prod/db" stays as it is.
    /// </summary>
    internal static string EntryName(string secretName)
    {
        var builder = new StringBuilder(secretName.Length + 8);
        foreach (var c in secretName)
        {
            if (char.IsAsciiLetterUpper(c))
                builder.Append(UpperCaseMarker).Append((char)(c + ('a' - 'A')));
            else
                builder.Append(c);
        }

        return builder.ToString();
    }

    /// <summary>The secret name <see cref="EntryName"/> made <paramref name="entryName"/> from.</summary>
    internal static string SecretName(string entryName)
    {
        var builder = new StringBuilder(entryName.Length);
        for (var i = 0; i < entryName.Length; i++)
        {
            if (entryName[i] == UpperCaseMarker)
                builder.Append((char)(entryName[++i] - ('a' - 'A')));
            else
                builder.Append(entryName[i]);
        }

        return builder.ToString();
    }

    // The entry a name is stored under: its secret's entry name, then '#' and the case-escaped key, if any.
    private bool TryGetEntryName(string name, out string entryName)
    {
        ArgumentNullException.ThrowIfNull(name);
        entryName = null!;

        var separator = name.IndexOf(KeySeparator);
        var secretName = separator < 0 ? name : name[..separator];
        var key = separator < 0 ? DefaultKey : name[(separator + 1)..];
        if ((key is not null && !IsValidKey(key))
            || !IsValidName(secretName)
            || (_matching == SecretNameMatching.Exact && secretName.Contains(UpperCaseMarker)))
            return false;

        entryName = SecretEntryName(secretName) + (key is null ? "" : KeySeparator + EntryName(key));
        return true;
    }

    private string SecretEntryName(string secretName) => _matching == SecretNameMatching.Exact ? EntryName(secretName) : secretName;

    // Fetches the secret stored under secretEntryName - through Fetch, synchronously, or FetchAsync -
    // caching everything handed over; false if nothing was. Synchronously, it never awaits anything
    // incomplete, so it returns completed.
    private async ValueTask<bool> PopulateAsync(string secretEntryName, bool synchronously, CancellationToken cancellationToken)
    {
        var secretName = _matching == SecretNameMatching.Exact ? SecretName(secretEntryName) : secretEntryName;
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Populate);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
        {
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Populate, (AttributeNames.Name, secretName));
            _logger?.SensitiveOperationLogged(ActivityNames.Cache.Populate, secretName);
        }

        var sink = new SecretValueSink(_store, secretEntryName);
        try
        {
            if (synchronously)
                Fetch(secretName, sink);
            else
                await FetchAsync(secretName, sink, cancellationToken).ConfigureAwait(false);
            sink.Close();
            if (sink.Values.Count == 0)
            {
                RecordOperation("not_found");
                return false;
            }

            // A fetch that began just after another finished may find values already stored; keep those.
            foreach (var (entryName, value) in sink.Values)
                _store.Add(entryName, value);
            RecordOperation("success");
            return true;
        }
        catch (Exception ex)
        {
            sink.Close();
            ComponentTelemetry.RecordException(activity, ex);
            _logger?.OperationFailed(ActivityNames.Cache.Populate, ex);
            RecordOperation("error");
            throw;
        }
    }

    private static void RecordOperation(string result)
        => CacheMetrics.Operations.Add(1,
            new KeyValuePair<string, object?>(AttributeNames.OperationName, ActivityNames.Cache.Populate),
            new KeyValuePair<string, object?>(AttributeNames.Result, result));

    internal sealed class Store(RemoteSecretCache owner, IKeyRing keyRing) : ProtectedCacheBase(keyRing)
    {
        // One fetch per uncached secret at a time, whichever of its names was asked for and however;
        // removed once it completes, whatever the outcome.
        private readonly ConcurrentDictionary<string, Task<bool>> _fetches = new(NameComparer);

        internal KeyTrackingValue EncryptEntry(string entryName, Span<byte> plaintext) => Encrypt(entryName, plaintext);

        internal void Add(string entryName, KeyTrackingValue value) => Data.TryAdd(entryName, value);

        // Fetches the secret name belongs to; ProtectedCacheBase then looks name up again.
        protected override bool TryPopulate(string name)
            => PopulateSharedAsync(name, synchronously: true, CancellationToken.None).GetAwaiter().GetResult();

        protected override ValueTask<bool> TryPopulateAsync(string name, CancellationToken cancellationToken)
            => PopulateSharedAsync(name, synchronously: false, cancellationToken);

        // Runs the secret's fetch, or waits for the one already running. Synchronously, it blocks
        // rather than awaits, so it returns completed.
        private async ValueTask<bool> PopulateSharedAsync(string name, bool synchronously, CancellationToken cancellationToken)
        {
            var separator = name.IndexOf(KeySeparator);
            var secretEntryName = separator < 0 ? name : name[..separator];

            while (true)
            {
                var fetch = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                var running = _fetches.GetOrAdd(secretEntryName, fetch.Task);
                if (running != fetch.Task)
                {
                    try
                    {
                        return synchronously
                            ? running.GetAwaiter().GetResult()
                            : await running.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (running.IsCanceled && !cancellationToken.IsCancellationRequested)
                    {
                        // Cancelled by the caller that started it, not by this one: fetch again.
                        continue;
                    }
                }

                try
                {
                    var populated = await owner.PopulateAsync(secretEntryName, synchronously, cancellationToken).ConfigureAwait(false);
                    fetch.SetResult(populated);
                    return populated;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    fetch.SetCanceled(cancellationToken);
                    throw;
                }
                catch (Exception ex)
                {
                    fetch.SetException(ex);

                    // Observed here, so a failure no other lookup waited on isn't reported as unobserved.
                    _ = fetch.Task.Exception;
                    throw;
                }
                finally
                {
                    _fetches.TryRemove(new KeyValuePair<string, Task<bool>>(secretEntryName, fetch.Task));
                }
            }
        }
    }
}

/// <summary>
/// Receives what <see cref="RemoteSecretCache.Fetch"/> read, and encrypts each value at once, bound
/// to its own name within the secret being fetched - nothing else can be stored through it, and it
/// refuses every call once that fetch has returned. Set the secret's whole value at most once, and
/// each key at most once; an empty value counts as none.
/// </summary>
public sealed class SecretValueSink
{
    private readonly RemoteSecretCache.Store _store;
    private readonly string _secretEntryName;
    private readonly Dictionary<string, KeyTrackingValue> _values = new(StringComparer.Ordinal);
    private bool _closed;

    internal SecretValueSink(RemoteSecretCache.Store store, string secretEntryName)
    {
        _store = store;
        _secretEntryName = secretEntryName;
    }

    /// <summary>Every value set, by the entry name it was encrypted under.</summary>
    internal IReadOnlyDictionary<string, KeyTrackingValue> Values => _values;

    /// <summary>Encrypts plaintext as the secret's whole value. plaintext is zeroed as a side effect.</summary>
    /// <exception cref="InvalidOperationException">The value was already set, or the fetch has returned</exception>
    public void SetBytes(Span<byte> plaintext) => Set(_secretEntryName, plaintext);

    /// <summary>
    /// Encrypts text's UTF-8 bytes as the secret's whole value. The bytes are zeroed once encrypted;
    /// text itself is read-only and is left as it is.
    /// </summary>
    /// <exception cref="InvalidOperationException">The value was already set, or the fetch has returned</exception>
    public void SetText(ReadOnlySpan<char> text)
    {
        EnsureUnset(_secretEntryName);

        // On the stack, or pinned when too large: never somewhere the GC can copy it.
        var byteCount = Encoding.UTF8.GetByteCount(text);
        Span<byte> plaintext = byteCount <= ArrayUtility.MaxStackBytes
            ? stackalloc byte[byteCount]
            : ArrayUtility.AllocatePinned<byte>(byteCount);
        Encoding.UTF8.GetBytes(text, plaintext);
        SetBytes(plaintext);
    }

    /// <summary>
    /// Encrypts plaintext as the value of one key the secret holds - looked up as "name#key".
    /// plaintext is zeroed as a side effect.
    /// </summary>
    /// <exception cref="ArgumentException">key isn't one a name can hold (see <see cref="RemoteSecretCache.IsValidKey"/>)</exception>
    /// <exception cref="InvalidOperationException">That key was already set, or the fetch has returned</exception>
    public void SetKeyBytes(string key, Span<byte> plaintext)
    {
        try
        {
            if (!RemoteSecretCache.IsValidKey(key))
                throw new ArgumentException($"'{key}' isn't a key: 1-{RemoteSecretCache.MaxKeyLength} printable ASCII characters other than space, '!' and '#'.", nameof(key));

            Set(_secretEntryName + RemoteSecretCache.KeySeparator + RemoteSecretCache.EntryName(key), plaintext);
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Encrypts plaintext as the secret's whole value and, when it is a JSON object - such as an AWS
    /// Secrets Manager key/value secret - each of its top-level members as a key: a string as its
    /// UTF-8 bytes, a number, true or false as its JSON text. A member that is null, an object or an
    /// array, or whose name isn't a key a name can hold, is left out. Anything that isn't a JSON
    /// object - plain text, an array, malformed JSON - is the whole value only. plaintext is zeroed
    /// as a side effect, and every buffer a member was unescaped into is zeroed once encrypted.
    /// </summary>
    /// <exception cref="InvalidDataException">The JSON object holds a member name more than once</exception>
    /// <exception cref="InvalidOperationException">The value or a key was already set, or the fetch has returned</exception>
    public void SetBytesWithJsonKeys(Span<byte> plaintext)
    {
        try
        {
            SecretJsonKeys.TrySetKeys(plaintext, this);
            SetBytes(plaintext);
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    internal void Close() => _closed = true;

    private void Set(string entryName, Span<byte> plaintext)
    {
        try
        {
            EnsureUnset(entryName);
            if (!plaintext.IsEmpty)
                _values.Add(entryName, _store.EncryptEntry(entryName, plaintext));
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    private void EnsureUnset(string entryName)
    {
        if (_closed)
            throw new InvalidOperationException("The fetch this value belongs to has already returned.");
        if (_values.ContainsKey(entryName))
            throw new InvalidOperationException("A value has already been set for this secret or key.");
    }
}
