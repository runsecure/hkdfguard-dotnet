using System.Collections.Concurrent;
using System.Text;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Abstractions;

/// <summary>
/// Shared IProtectedReadOnlyCache plumbing for every cache in this library: an IKeyRing to encrypt
/// and decrypt through, a ConcurrentDictionary of encrypted entries keyed by name, and the
/// encrypt/decrypt/telemetry logic every concrete cache needs. Decrypt/TryGetMaxDecryptedLength
/// fall back to TryPopulate on a miss before giving up - the default implementation here just
/// returns false (nothing to pull from), but a subclass backed by an external source (e.g. a remote
/// secret store) overrides it to fetch the plaintext value and encrypt it into Data on demand, so
/// nothing here ever holds plaintext beyond the duration of a single call.
/// <para>
/// <b>Keys come from the ring, so the cache follows rotation.</b> Every value is encrypted under the
/// ring's current key at the moment it is stored, and its entry records that key's version. Decrypt
/// uses exactly that version, so values stored before a rotation still decrypt while new values use
/// the new key. The cache never owns or disposes keys; the ring does.
/// </para>
/// <para>
/// <b>Every entry is bound to its name.</b> Each value is encrypted with Additional Authenticated
/// Data derived from the name it is stored under (see <see cref="AadFor"/>), and decrypted with the
/// AAD of the name it is looked up by. A ciphertext that ends up under any other name - through a
/// TryPopulate bug, or an entry copied or swapped in Data - fails authentication rather than
/// decrypting as that name's value.
/// </para>
/// <para>
/// Names are matched ignoring ASCII case only (<see cref="NameComparer"/>): "Item" and "ITEM" are
/// one entry, but "café" and "CAFÉ" are two. The AAD follows exactly the same rule, so every
/// spelling that reaches an entry also authenticates against it. This is the same case rule
/// ProtectedConfigurationPurpose uses, chosen for the same reason: .NET's OrdinalIgnoreCase can't be
/// reproduced as a byte rule, so an AAD can't follow it.
/// </para>
/// </summary>
public abstract class ProtectedCacheBase(IKeyRing keyRing) : IProtectedReadOnlyCache
{
    /// <summary>The prefix of every cache entry's AAD, keeping it distinct from any other purpose.</summary>
    public const string AadPrefix = "HkdfGuard.Cache:";

    // AADs up to this many bytes are built on the stack.
    private const int MaxStackAadBytes = 512;

    // Throws on an unpaired surrogate instead of substituting U+FFFD, which would give two
    // different (invalid) names the same AAD.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// How names are matched: ignoring ASCII case, comparing every other character exactly. Any
    /// replacement for <see cref="Data"/> must use this comparer, or a name could reach an entry
    /// whose AAD it doesn't produce.
    /// </summary>
    protected static IEqualityComparer<string> NameComparer => AsciiIgnoreCaseComparer.Instance;

    /// <summary>
    /// The encrypted entries this cache holds - each a ciphertext with the key version it was
    /// encrypted under - keyed by <see cref="NameComparer"/>. Protected so concrete caches (e.g.
    /// ProtectedCache's Add/AddOrUpdate) can populate it directly - always with an entry from
    /// <see cref="Encrypt"/> or <see cref="EncryptChars"/> for that same name.
    /// </summary>
    protected ConcurrentDictionary<string, KeyTrackingValue> Data = new(AsciiIgnoreCaseComparer.Instance);

    /// <summary>
    /// The Additional Authenticated Data a value stored under <paramref name="name"/> is bound to:
    /// the UTF-8 bytes of <see cref="AadPrefix"/> + name, with ASCII a-z upper-cased.
    /// </summary>
    /// <exception cref="ArgumentNullException">name is null</exception>
    /// <exception cref="ArgumentException">name is not valid UTF-16 (an unpaired surrogate)</exception>
    public static byte[] AadFor(string name)
    {
        var aad = new byte[AadLength(name)];
        WriteAad(name, aad);
        return aad;
    }

    /// <summary>
    /// Called when name isn't already in Data, before Decrypt/TryGetMaxDecryptedLength give
    /// up and return false. The default implementation does nothing - override to pull a value in
    /// from an external source and store it in Data (via Encrypt/EncryptChars, for this same
    /// name) before returning true.
    /// </summary>
    /// <param name="name">The name that was missing from Data</param>
    /// <returns>True if name was successfully populated into Data as a result of this call</returns>
    protected virtual bool TryPopulate(string name) => false;

    /// <inheritdoc/>
    /// <exception cref="KeyNotFoundException">The entry's key version is no longer in the ring</exception>
    public int Decrypt(string name, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.Root.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Root.EnableSensitiveLogging)
            HkdfGuardTelemetry.Root.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));

        try
        {
            if (!TryGetEntry(name, out var entry))
                return 0;

            var key = keyRing.Get(entry.KeyVersion);
            var aadLength = AadLength(name);
            Span<byte> aad = aadLength <= MaxStackAadBytes ? stackalloc byte[aadLength] : new byte[aadLength];
            WriteAad(name, aad);

            return key.Decrypt(entry.Value, aad, result);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="KeyNotFoundException">The entry's key version is no longer in the ring</exception>
    public int Decrypt(string name, Span<char> result)
    {
        using var activity = HkdfGuardTelemetry.Root.ActivitySource.StartActivity(ActivityNames.Cache.Decrypt);
        if (HkdfGuardTelemetry.Root.EnableSensitiveLogging)
            HkdfGuardTelemetry.Root.LogSensitiveOperation(activity, ActivityNames.Cache.Decrypt, (AttributeNames.Name, name));

        try
        {
            if (!TryGetEntry(name, out var entry))
                return 0;

            var key = keyRing.Get(entry.KeyVersion);
            var aadLength = AadLength(name);
            Span<byte> aad = aadLength <= MaxStackAadBytes ? stackalloc byte[aadLength] : new byte[aadLength];
            WriteAad(name, aad);

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // entry.Value.Length is a safe upper bound for the decrypted UTF8 byte count. On the
            // stack, or pinned when too large: never somewhere the GC can copy it, nor a pooled
            // array another caller would later be handed.
            var encrypted = entry.Value;
            Span<byte> plaintextBytes = encrypted.Length <= ArrayUtility.MaxStackBytes
                ? stackalloc byte[encrypted.Length]
                : ArrayUtility.AllocatePinned<byte>(encrypted.Length);
            try
            {
                var decryptedLength = key.Decrypt(encrypted, aad, plaintextBytes);
                return Encoding.UTF8.GetChars(plaintextBytes[..decryptedLength], result);
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
    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        if (TryGetEntry(name, out var entry))
        {
            maxLength = entry.Value.Length;
            return true;
        }

        maxLength = 0;
        return false;
    }

    private bool TryGetEntry(string name, out KeyTrackingValue entry)
    {
        if (Data.TryGetValue(name, out entry!))
            return true;

        if (TryPopulate(name) && Data.TryGetValue(name, out entry!))
            return true;

        entry = null!;
        return false;
    }

    /// <summary>
    /// Encrypts plaintext under the ring's current key, bound to <paramref name="name"/> - store
    /// the result in Data under that same name. The entry records the key version, so it keeps
    /// decrypting after the ring rotates. plaintext is zeroed as a side effect.
    /// </summary>
    /// <exception cref="ArgumentException">plaintext is empty - Decrypt reports a missing name as
    /// 0 bytes, so an empty value would be indistinguishable from no value - or name is not valid
    /// UTF-16</exception>
    /// <exception cref="InvalidOperationException">The ring has no key yet</exception>
    protected KeyTrackingValue Encrypt(string name, Span<byte> plaintext)
    {
        if (plaintext.IsEmpty)
            throw new ArgumentException("An empty value cannot be cached: Decrypt reports a missing name as 0 bytes.", nameof(plaintext));

        try
        {
            var aadLength = AadLength(name);
            Span<byte> aad = aadLength <= MaxStackAadBytes ? stackalloc byte[aadLength] : new byte[aadLength];
            WriteAad(name, aad);

            // Resolved on every call, so a value stored after a rotation uses the new key.
            var (version, key) = keyRing.GetCurrent();
            return new KeyTrackingValue { KeyVersion = version, Value = key.Encrypt(plaintext, aad) };
        }
        finally
        {
            // Normally already done by the key; this covers a failure before encrypting.
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Encrypts plaintext (as UTF8 bytes) under the ring's current key, bound to
    /// <paramref name="name"/> - store the result in Data under that same name. plaintext is
    /// zeroed as a side effect - callers that only hold a string must copy it into a caller-owned
    /// Span&lt;char&gt; (e.g. via stackalloc) first, since a string's own backing buffer can't be
    /// safely cleared.
    /// </summary>
    /// <exception cref="ArgumentException">plaintext is empty, or name is not valid UTF-16 - see <see cref="Encrypt"/></exception>
    /// <exception cref="InvalidOperationException">The ring has no key yet</exception>
    protected KeyTrackingValue EncryptChars(string name, Span<char> plaintext)
    {
        if (plaintext.IsEmpty)
            throw new ArgumentException("An empty value cannot be cached: Decrypt reports a missing name as 0 bytes.", nameof(plaintext));

        // On the stack, or pinned when too large: never somewhere the GC can copy it.
        var byteCount = Encoding.UTF8.GetByteCount(plaintext);
        Span<byte> plaintextBytes = byteCount <= ArrayUtility.MaxStackBytes
            ? stackalloc byte[byteCount]
            : ArrayUtility.AllocatePinned<byte>(byteCount);
        try
        {
            Encoding.UTF8.GetBytes(plaintext, plaintextBytes);
            return Encrypt(name, plaintextBytes);
        }
        finally
        {
            // Zeroed here, not left to whichever IDataEncryptionKey/provider is underneath.
            ArrayUtility.ZeroMemory(plaintextBytes);
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    private static int AadLength(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return AadPrefix.Length + StrictUtf8.GetByteCount(name);
    }

    // AadPrefix + the name's UTF-8 bytes, with ASCII a-z upper-cased. Upper-casing at the byte level
    // is exact: in UTF-8, bytes 0x61-0x7A only ever encode those ASCII letters.
    private static void WriteAad(string name, Span<byte> destination)
    {
        Encoding.ASCII.GetBytes(AadPrefix, destination);
        var nameBytes = destination[AadPrefix.Length..];
        StrictUtf8.GetBytes(name, nameBytes);
        for (var i = 0; i < nameBytes.Length; i++)
        {
            if (nameBytes[i] is >= (byte)'a' and <= (byte)'z')
                nameBytes[i] -= 'a' - 'A';
        }
    }

    private sealed class AsciiIgnoreCaseComparer : IEqualityComparer<string>
    {
        public static readonly AsciiIgnoreCaseComparer Instance = new();

        public bool Equals(string? x, string? y)
        {
            if (ReferenceEquals(x, y))
                return true;
            if (x is null || y is null || x.Length != y.Length)
                return false;

            for (var i = 0; i < x.Length; i++)
            {
                if (ToUpperAscii(x[i]) != ToUpperAscii(y[i]))
                    return false;
            }

            return true;
        }

        public int GetHashCode(string obj)
        {
            var hash = new HashCode();
            foreach (var c in obj)
                hash.Add(ToUpperAscii(c));
            return hash.ToHashCode();
        }

        private static char ToUpperAscii(char c) => char.IsAsciiLetterLower(c) ? (char)(c - ('a' - 'A')) : c;
    }
}
