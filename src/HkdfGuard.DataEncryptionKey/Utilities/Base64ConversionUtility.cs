using System.Buffers.Text;

namespace HkdfGuard.DataEncryptionKey.Utilities;

public static class Base64ConversionUtility
{
    /// <summary>
    /// Checks whether a char span or string is valid base64 text
    /// </summary>
    /// <param name="base64">The text to validate (a string implicitly converts to a span)</param>
    /// <returns>True if every char is valid base64 text</returns>
    public static bool IsBase64(ReadOnlySpan<char> base64)
        => Base64.IsValid(base64);

    /// <summary>
    /// Checks whether a byte span holds base64 text encoded as ASCII/UTF-8 bytes
    /// </summary>
    /// <param name="base64">The bytes to validate</param>
    /// <returns>True if every byte is a valid base64 character byte</returns>
    public static bool IsBase64(ReadOnlySpan<byte> base64)
        => Base64.IsValid(base64);

    /// <summary>
    /// Computes the decoded binary length for a base64-encoded char span or string
    /// </summary>
    /// <param name="base64">The base64 text (a string implicitly converts to a span)</param>
    /// <returns>The number of bytes the decoded data will occupy</returns>
    public static int GetBinaryLength(ReadOnlySpan<char> base64)
    {
        if (base64.IsEmpty)
            return 0;

        if (base64.Length % 4 != 0)
            throw new FormatException("Base64 input length must be a multiple of 4.");

        var padding = 0;
        if (base64[^1] == '=') padding++;
        if (base64[^2] == '=') padding++;

        return base64.Length / 4 * 3 - padding;
    }

    /// <summary>
    /// Computes the base64-encoded char length for a span of bytes
    /// </summary>
    /// <param name="data">The binary data to be encoded</param>
    /// <returns>The number of chars the base64 encoded output will occupy</returns>
    public static int GetBase64Length(ReadOnlySpan<byte> data)
        => data.IsEmpty ? 0 : (data.Length + 2) / 3 * 4;

    /// <summary>
    /// Decodes base64 text into its binary representation
    /// </summary>
    /// <param name="base64">The base64 text to decode (a string implicitly converts to a span)</param>
    /// <param name="destination">The span to receive the decoded bytes</param>
    /// <returns>Number of bytes written to the destination</returns>
    public static int FromBase64(ReadOnlySpan<char> base64, Span<byte> destination)
    {
        return Convert.TryFromBase64Chars(base64, destination, out var bytesWritten)
            ? bytesWritten
            : throw new FormatException("Input is not valid base64, or the destination buffer is too small.");
    }

    /// <summary>
    /// Encodes binary data as a base64 string
    /// </summary>
    /// <param name="data">The binary data to encode</param>
    /// <returns>The base64 encoded string</returns>
    public static string ToBase64String(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data);

    /// <summary>
    /// Encodes binary data as base64 into a char span
    /// </summary>
    /// <param name="data">The binary data to encode</param>
    /// <param name="destination">The span to receive the base64 encoded chars</param>
    /// <returns>Number of chars written to the destination</returns>
    public static int ToBase64Chars(ReadOnlySpan<byte> data, Span<char> destination)
    {
        return Convert.TryToBase64Chars(data, destination, out var charsWritten)
            ? charsWritten
            : throw new ArgumentException("Destination span too small.", nameof(destination));
    }
}
