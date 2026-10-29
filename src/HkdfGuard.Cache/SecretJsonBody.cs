using System.Buffers.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache;

/// <summary>
/// Takes a secret out of a JSON response body before an SDK can turn it into a string. The body is
/// read into pinned memory, the named string property is unescaped (and base64-decoded,
/// for a binary property) straight into pinned memory and handed to a <see cref="SecretValueSink"/>,
/// and what's returned is the same body with that value replaced by "" - for the SDK to parse as
/// usual, holding nothing secret. Every buffer that held the value is zeroed before returning.
/// </summary>
public static class SecretJsonBody
{
    /// <summary>The largest body read: far beyond any secret store's response, so a larger one is refused.</summary>
    public const int MaxBodyLength = 1024 * 1024;

    private const int InitialBufferLength = 16 * 1024;

    /// <summary>
    /// Reads body to its end, hands the value of its top-level <paramref name="textProperty"/> (as
    /// UTF-8 bytes, with <see cref="SecretValueSink.SetBytesWithJsonKeys"/>, so a JSON object's
    /// members are keys too) or <paramref name="base64Property"/> (as the bytes it encodes, whole) to
    /// value, and returns the body with both values replaced by "". A missing, null or empty property
    /// hands nothing over. body is read but not disposed.
    /// </summary>
    /// <exception cref="InvalidDataException">body isn't a JSON object, is <see cref="MaxBodyLength"/>
    /// bytes or more, holds more than one non-empty secret value, or a base64 value that isn't base64;
    /// or the text value is a JSON object holding a member name more than once</exception>
    public static byte[] Capture(Stream body, SecretValueSink value, string textProperty, string? base64Property = null)
        => Capture(body, value, [], textProperty, base64Property);

    /// <summary>
    /// As <see cref="Capture(Stream, SecretValueSink, string, string?)"/>, for a value nested in
    /// objects: <paramref name="textProperty"/> and <paramref name="base64Property"/> are looked for
    /// in the object reached through <paramref name="objectPath"/>'s property names - ["data", "data"]
    /// for {"data":{"data":{"value":"..."}}}. A path that leads to no object hands nothing over.
    /// </summary>
    /// <exception cref="InvalidDataException">body isn't a JSON object, is <see cref="MaxBodyLength"/>
    /// bytes or more, holds more than one non-empty secret value, or a base64 value that isn't base64;
    /// or the text value is a JSON object holding a member name more than once</exception>
    public static byte[] Capture(Stream body, SecretValueSink value, ReadOnlySpan<string> objectPath, string textProperty, string? base64Property = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(textProperty);
        return Read(body, value, objectPath, new Target(textProperty, base64Property, value));
    }

    /// <summary>
    /// Reads body to its end and hands each member of the object reached through
    /// <paramref name="objectPath"/>'s property names to value as a key, as
    /// <see cref="SecretValueSink.SetBytesWithJsonKeys"/> describes - for a store whose secrets are
    /// sets of keys, such as HashiCorp Vault's KV: ["data", "data"] for
    /// {"data":{"data":{"username":"...","password":"..."}}}. A path that leads to no object hands
    /// nothing over. body is read but not disposed.
    /// </summary>
    /// <exception cref="InvalidDataException">body isn't a JSON object, or is <see cref="MaxBodyLength"/>
    /// bytes or more; or the object holds a member name more than once</exception>
    public static void CaptureKeys(Stream body, SecretValueSink value, ReadOnlySpan<string> objectPath)
        => Read(body, value, objectPath, new Target(null, null, value));

    /// <summary>
    /// <see cref="Capture(Stream, SecretValueSink, string, string?)"/>, reading body asynchronously
    /// into the same pinned memory.
    /// </summary>
    /// <exception cref="InvalidDataException">As for <see cref="Capture(Stream, SecretValueSink, string, string?)"/></exception>
    public static Task<byte[]> CaptureAsync(Stream body, SecretValueSink value, string textProperty, string? base64Property = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(textProperty);
        return ReadAsync(body, value, [], new Target(textProperty, base64Property, value), cancellationToken);
    }

    /// <summary>
    /// <see cref="CaptureKeys"/>, reading body asynchronously into the same pinned memory.
    /// </summary>
    /// <exception cref="InvalidDataException">As for <see cref="CaptureKeys"/></exception>
    public static Task CaptureKeysAsync(Stream body, SecretValueSink value, string[] objectPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(objectPath);
        return ReadAsync(body, value, objectPath, new Target(null, null, value), cancellationToken);
    }

    // Reads body into pinned memory and walks it for target; returns the body redacted, for a target
    // with a text property.
    private static byte[] Read(Stream body, SecretValueSink value, ReadOnlySpan<string> objectPath, Target target)
    {
        CheckArguments(body, value, objectPath);
        var (buffer, length) = ReadPinned(body);
        return Parse(buffer, length, objectPath, target);
    }

    private static async Task<byte[]> ReadAsync(Stream body, SecretValueSink value, string[] objectPath, Target target, CancellationToken cancellationToken)
    {
        CheckArguments(body, value, objectPath);
        var (buffer, length) = await ReadPinnedAsync(body, cancellationToken).ConfigureAwait(false);
        return Parse(buffer, length, objectPath, target);
    }

    private static void CheckArguments(Stream body, SecretValueSink value, ReadOnlySpan<string> objectPath)
    {
        ArgumentNullException.ThrowIfNull(body);
        ArgumentNullException.ThrowIfNull(value);
        foreach (var name in objectPath)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("A property name in the path is null or empty.", nameof(objectPath));
        }
    }

    // Walks the body read into buffer for target, then zeroes buffer.
    private static byte[] Parse(byte[] buffer, int length, ReadOnlySpan<string> objectPath, Target target)
    {
        try
        {
            var json = buffer.AsSpan(0, length);
            var reader = new Utf8JsonReader(json);
            try
            {
                if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                    throw new InvalidDataException("The response body isn't a JSON object.");

                ReadObject(ref reader, objectPath, target);
            }
            catch (JsonException e)
            {
                // Not chained: the reader's message quotes the byte it rejected, which may be in the secret.
                throw new InvalidDataException($"The response body isn't valid JSON (at byte {e.BytePositionInLine} of line {e.LineNumber}).");
            }

            return target.TextProperty is null ? [] : Redact(json, target.Secrets);
        }
        finally
        {
            ArrayUtility.ZeroMemory(buffer);
        }
    }

    // What one read looks for - a text (and base64) property, or, with no text property, every
    // member as a key - and what it has found so far.
    private sealed class Target(string? textProperty, string? base64Property, SecretValueSink value)
    {
        public string? TextProperty { get; } = textProperty;
        public string? Base64Property { get; } = base64Property;
        public SecretValueSink Value { get; } = value;
        public List<(int Start, int End)> Secrets { get; } = new(2);
        public HashSet<string> Keys { get; } = new(StringComparer.Ordinal);
        public bool HandedOver { get; set; }
    }

    // Reads the properties of the object reader is at the start of, descending objectPath; returns
    // with reader at its end.
    private static void ReadObject(ref Utf8JsonReader reader, ReadOnlySpan<string> objectPath, Target target)
    {
        if (objectPath.IsEmpty && target.TextProperty is null)
        {
            SecretJsonKeys.SetKeys(ref reader, target.Value, target.Keys);
            return;
        }

        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (!objectPath.IsEmpty)
            {
                var isParent = reader.ValueTextEquals(objectPath[0]);
                reader.Read();
                if (isParent && reader.TokenType == JsonTokenType.StartObject)
                    ReadObject(ref reader, objectPath[1..], target);
                else
                    reader.Skip();
                continue;
            }

            ReadProperty(ref reader, target);
        }
    }

    // Reads the property reader is at the name of, in the object holding the secret.
    private static void ReadProperty(ref Utf8JsonReader reader, Target target)
    {
        var isText = reader.ValueTextEquals(target.TextProperty);
        var isBase64 = !isText && target.Base64Property is not null && reader.ValueTextEquals(target.Base64Property);
        reader.Read();

        if (!(isText || isBase64) || reader.TokenType != JsonTokenType.String)
        {
            reader.Skip();
            return;
        }

        if (!reader.ValueSpan.IsEmpty)
        {
            if (target.HandedOver)
                throw new InvalidDataException("The response body holds more than one secret value.");

            HandOver(ref reader, isBase64, target.Value);
            target.HandedOver = true;
        }

        target.Secrets.Add(((int)reader.TokenStartIndex, (int)reader.BytesConsumed));
    }

    private static void HandOver(ref Utf8JsonReader reader, bool isBase64, SecretValueSink value)
    {
        // Unescaped, a string is never longer than it is escaped.
        var text = ArrayUtility.AllocatePinned<byte>(reader.ValueSpan.Length);
        try
        {
            var textLength = reader.CopyString(text);
            if (!isBase64)
            {
                value.SetBytesWithJsonKeys(text.AsSpan(0, textLength));
                return;
            }

            var bytes = ArrayUtility.AllocatePinned<byte>(Base64.GetMaxDecodedFromUtf8Length(textLength));
            try
            {
                if (Base64.DecodeFromUtf8(text.AsSpan(0, textLength), bytes, out _, out var written) != System.Buffers.OperationStatus.Done)
                    throw new InvalidDataException("The response body's binary secret value isn't base64.");

                value.SetBytes(bytes.AsSpan(0, written));
            }
            finally
            {
                ArrayUtility.ZeroMemory(bytes);
            }
        }
        finally
        {
            ArrayUtility.ZeroMemory(text);
        }
    }

    // The body with each secret value's token - its quotes included - replaced by "".
    private static byte[] Redact(ReadOnlySpan<byte> json, List<(int Start, int End)> secrets)
    {
        var length = json.Length;
        foreach (var (start, end) in secrets)
            length -= end - start - 2;

        var redacted = new byte[length];
        var from = 0;
        var to = 0;
        foreach (var (start, end) in secrets)
        {
            json[from..start].CopyTo(redacted.AsSpan(to));
            to += start - from;
            redacted[to++] = (byte)'"';
            redacted[to++] = (byte)'"';
            from = end;
        }

        json[from..].CopyTo(redacted.AsSpan(to));
        return redacted;
    }

    // The whole body, in pinned memory: never somewhere the GC can copy it, nor a pooled array.
    private static (byte[] Buffer, int Length) ReadPinned(Stream body)
    {
        var buffer = ArrayUtility.AllocatePinned<byte>(InitialBufferLength);
        var length = 0;
        try
        {
            int read;
            while ((read = body.Read(buffer.AsSpan(length))) > 0)
            {
                length += read;
                buffer = GrowIfFull(buffer, length);
            }

            return (buffer, length);
        }
        catch
        {
            ArrayUtility.ZeroMemory(buffer);
            throw;
        }
    }

    // As ReadPinned: the array behind the Memory each read fills is pinned too.
    private static async Task<(byte[] Buffer, int Length)> ReadPinnedAsync(Stream body, CancellationToken cancellationToken)
    {
        var buffer = ArrayUtility.AllocatePinned<byte>(InitialBufferLength);
        var length = 0;
        try
        {
            int read;
            while ((read = await body.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                length += read;
                buffer = GrowIfFull(buffer, length);
            }

            return (buffer, length);
        }
        catch
        {
            ArrayUtility.ZeroMemory(buffer);
            throw;
        }
    }

    // buffer, or once it's full a pinned copy twice its size, the original zeroed.
    private static byte[] GrowIfFull(byte[] buffer, int length)
    {
        if (length < buffer.Length)
            return buffer;
        if (buffer.Length >= MaxBodyLength)
            throw new InvalidDataException($"The response body is {MaxBodyLength} bytes or more.");

        var larger = ArrayUtility.AllocatePinned<byte>(Math.Min(buffer.Length * 2, MaxBodyLength));
        buffer.AsSpan(0, length).CopyTo(larger);
        ArrayUtility.ZeroMemory(buffer);
        return larger;
    }
}
