using System.Collections.Concurrent;
using System.Text;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.ConfigurationResolver.Test.TestHelpers;

/// <summary>
/// Test-only: an IProtectedReadOnlyCache over plain strings, names matched exactly, that counts every
/// lookup by name and can run a callback the first time it decrypts a name. A real cache never holds
/// plaintext like this.
/// </summary>
internal sealed class PlainSource : IProtectedReadOnlyCache
{
    private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

    public ConcurrentDictionary<string, int> Decrypts { get; } = new(StringComparer.Ordinal);

    public ConcurrentDictionary<string, int> LengthLookups { get; } = new(StringComparer.Ordinal);

    /// <summary>Runs once, the first time the given name is decrypted.</summary>
    public (string Name, Action Action)? OnFirstDecrypt { get; set; }

    public string this[string name]
    {
        set => _values[name] = value;
    }

    public int DecryptCount(string name) => Decrypts.GetValueOrDefault(name);

    public int LengthLookupCount(string name) => LengthLookups.GetValueOrDefault(name);

    public int Decrypt(string name, Span<byte> result)
    {
        if (!TryRead(name, out var value))
            return 0;

        return Encoding.UTF8.GetBytes(value, result);
    }

    public int Decrypt(string name, Span<char> result)
    {
        if (!TryRead(name, out var value))
            return 0;

        value.CopyTo(result);
        return value.Length;
    }

    public bool TryGetMaxDecryptedLength(string name, out int maxLength)
    {
        LengthLookups.AddOrUpdate(name, 1, (_, count) => count + 1);
        maxLength = _values.TryGetValue(name, out var value) ? Encoding.UTF8.GetByteCount(value) : 0;
        return value is not null;
    }

    private bool TryRead(string name, out string value)
    {
        Decrypts.AddOrUpdate(name, 1, (_, count) => count + 1);
        if (OnFirstDecrypt is { } hook && hook.Name == name)
        {
            OnFirstDecrypt = null;
            hook.Action();
        }

        return _values.TryGetValue(name, out value!);
    }
}
