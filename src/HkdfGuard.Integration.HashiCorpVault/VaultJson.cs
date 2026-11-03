using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// How requests and responses are (de)serialized: nulls left out of requests, and responses read
/// leniently where Vault's answers stray from its spec - a number where a string is declared (a TTL in
/// seconds where the spec says duration string), a number in a string, a date-time with nanoseconds.
/// </summary>
internal static class VaultJson
{
    // The protector the token converter protects tokens with: set around each deserialization, which
    // runs synchronously on one thread.
    [ThreadStatic]
    private static IDataProtector? t_tokenProtector;

    public static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        };
        options.Converters.Add(new LenientStringConverter());
        options.Converters.Add(new DateTimeOffsetConverter());
        options.Converters.Add(new NullableDateTimeOffsetConverter());
        options.Converters.Add(new ProtectedTokenConverter());
        options.MakeReadOnly();
        return options;
    }

    /// <summary>Reads json as a T, protecting any token in it with tokenProtector.</summary>
    public static T? Deserialize<T>(ReadOnlySpan<byte> json, IDataProtector tokenProtector)
    {
        var previous = t_tokenProtector;
        t_tokenProtector = tokenProtector;
        try
        {
            return JsonSerializer.Deserialize<T>(json, Options);
        }
        finally
        {
            t_tokenProtector = previous;
        }
    }

    /// <summary>Writes value as JSON into output.</summary>
    public static void Serialize(IBufferWriter<byte> output, object value)
    {
        using var writer = new Utf8JsonWriter(output);
        JsonSerializer.Serialize(writer, value, value.GetType(), Options);
    }

    // A string, or whatever JSON stands in a string's place as its text.
    private sealed class LenientStringConverter : JsonConverter<string>
    {
        // Responses are always read from one span, so a value is never a ValueSequence; and a null
        // never reaches a converter.
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.TokenType switch
        {
            JsonTokenType.Number => Encoding.UTF8.GetString(reader.ValueSpan),
            JsonTokenType.True => "true",
            JsonTokenType.False => "false",
            JsonTokenType.StartObject or JsonTokenType.StartArray => ReadRaw(ref reader),
            _ => reader.GetString(),
        };

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) => writer.WriteStringValue(value);

        public override string ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString()!;

        public override void WriteAsPropertyName(Utf8JsonWriter writer, string value, JsonSerializerOptions options) => writer.WritePropertyName(value);

        private static string ReadRaw(ref Utf8JsonReader reader)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            return document.RootElement.GetRawText();
        }
    }

    private sealed class DateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => ParseDateTime(ref reader) ?? default;

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) => writer.WriteStringValue(value);
    }

    // An empty string is no time at all.
    private sealed class NullableDateTimeOffsetConverter : JsonConverter<DateTimeOffset?>
    {
        public override DateTimeOffset? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => ParseDateTime(ref reader);

        // Never handed a null: the serializer writes those itself.
        public override void Write(Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options) => writer.WriteStringValue(value!.Value);
    }

    // RFC 3339, as Go writes it: up to nine fractional digits, of which .NET keeps seven.
    private static DateTimeOffset? ParseDateTime(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException($"Expected a date-time string, not {reader.TokenType}.");

        var text = reader.GetString()!;
        if (text.Length == 0)
            return null;

        var dot = text.IndexOf('.');
        if (dot >= 0)
        {
            var end = dot + 1;
            while (end < text.Length && char.IsAsciiDigit(text[end]))
                end++;
            if (end - dot - 1 > 7)
                text = string.Concat(text.AsSpan(0, dot + 8), text.AsSpan(end));
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time)
            ? time
            : throw new JsonException($"'{reader.GetString()}' isn't a date-time.");
    }

    // A token in a response, protected as it is read: unescaped into stack or pinned memory, encrypted
    // from there, the plaintext zeroed - it never becomes a string. Written back in protected form.
    private sealed class ProtectedTokenConverter : JsonConverter<StaticVaultToken>
    {
        public override StaticVaultToken? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException($"Expected a token string, not {reader.TokenType}.");

            var protector = t_tokenProtector
                            ?? throw new InvalidOperationException("A Vault token can only be read by a VaultClient, which protects it.");

            // UTF-8 never takes fewer bytes than UTF-16 takes chars, and unescaping only shortens. Read
            // from one span, so never a ValueSequence.
            var maxLength = reader.ValueSpan.Length;
            if (maxLength == 0)
                return null;

            Span<char> chars = maxLength <= ArrayUtility.MaxStackChars ? stackalloc char[maxLength] : ArrayUtility.AllocatePinned<char>(maxLength);
            try
            {
                var token = chars[..reader.CopyString(chars)];
                if (!VaultHttp.IsValidToken(token))
                    throw new JsonException("Vault returned a token that isn't one: printable ASCII, with no spaces.");

                return new StaticVaultToken(protector.Encrypt(token));
            }
            finally
            {
                ArrayUtility.ZeroMemory(chars);
            }
        }

        public override void Write(Utf8JsonWriter writer, StaticVaultToken value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());
    }
}
