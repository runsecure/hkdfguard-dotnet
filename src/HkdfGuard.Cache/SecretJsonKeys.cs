using System.Text.Json;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache;

// Hands a JSON object's members to a SecretValueSink as keys, never as strings: each value is
// unescaped (or, for a number, true or false, copied) into pinned memory, handed over, and zeroed.
internal static class SecretJsonKeys
{
    /// <summary>
    /// When json is exactly one JSON object, hands each of its members over as a key; anything else
    /// - plain text that merely starts like JSON included - hands nothing over. The whole value is
    /// checked first, so malformed JSON never hands over part of its members.
    /// </summary>
    public static void TrySetKeys(ReadOnlySpan<byte> json, SecretValueSink value)
    {
        if (!IsObject(json))
            return;

        var reader = new Utf8JsonReader(json);
        reader.Read();
        SetKeys(ref reader, value, new HashSet<string>(StringComparer.Ordinal));
    }

    /// <summary>
    /// Hands each member of the object reader is at the start of over as a key, leaving reader at
    /// its end. A string is handed over as its UTF-8 bytes; a number, true or false as its JSON text;
    /// null, an object, an array, an empty string, or a member whose name isn't a key a name can
    /// hold, isn't handed over. <paramref name="seen"/> collects the member names, across every
    /// object handed over for one secret.
    /// </summary>
    /// <exception cref="InvalidDataException">A member name is in seen already</exception>
    public static void SetKeys(ref Utf8JsonReader reader, SecretValueSink value, HashSet<string> seen)
    {
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            var key = reader.GetString()!;
            if (!seen.Add(key))
                throw new InvalidDataException($"The secret holds the key '{key}' more than once.");

            reader.Read();
            if (RemoteSecretCache.IsValidKey(key) && reader.TokenType is JsonTokenType.String or JsonTokenType.Number or JsonTokenType.True or JsonTokenType.False)
                SetKey(ref reader, key, value);
            else
                reader.Skip();
        }
    }

    private static void SetKey(ref Utf8JsonReader reader, string key, SecretValueSink value)
    {
        // Unescaped, a string is never longer than it is escaped; anything else is copied as it is.
        var buffer = ArrayUtility.AllocatePinned<byte>(reader.ValueSpan.Length);
        try
        {
            var length = reader.TokenType == JsonTokenType.String ? reader.CopyString(buffer) : Copy(reader.ValueSpan, buffer);
            value.SetKeyBytes(key, buffer.AsSpan(0, length));
        }
        finally
        {
            ArrayUtility.ZeroMemory(buffer);
        }
    }

    private static int Copy(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        source.CopyTo(destination);
        return source.Length;
    }

    // One JSON object and nothing after it but whitespace.
    private static bool IsObject(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json);
        try
        {
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return false;

            reader.Skip();
            return !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
