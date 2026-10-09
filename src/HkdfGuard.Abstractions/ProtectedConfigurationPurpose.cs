using System.Buffers;
using System.Text;

namespace HkdfGuard.Abstractions;

/// <summary>
/// The single rule for binding an encrypted configuration value to the configuration key it's
/// stored under. Whoever writes a value (e.g. a pipeline via IPipelineDataProtector) and whoever
/// reads it (ProtectedConfigurationRoot) must derive the same purpose, so a value copied to a
/// different key fails authentication instead of being accepted. Keys are full configuration
/// paths (e.g. "ConnectionStrings:Admin").
/// <para>
/// The rule, which every language port implements identically: the purpose is
/// <c>"HkdfGuard.EncryptedConfiguration:" + key</c> with the ASCII letters a-z upper-cased and every
/// other UTF-16 code unit left exactly as it is; the AAD is that purpose's UTF-8 bytes (an unpaired
/// surrogate encodes as U+FFFD). It deliberately does not follow .NET configuration's
/// OrdinalIgnoreCase: that comparison depends on the runtime's Unicode tables, which change between
/// versions and which no other language reproduces, so a non-ASCII rule could not give the same
/// purpose everywhere.
/// </para>
/// <para>
/// The trade-off is one-sided and safe. Keys differing only in ASCII case share a purpose, as in
/// configuration. Keys differing in any other way - including non-ASCII case, such as "café" and
/// "CAFÉ" - never do, even where configuration treats them as one key; reading a value under such a
/// variant fails authentication rather than revealing it. No two keys configuration keeps apart
/// can ever share a purpose.
/// </para>
/// </summary>
public static class ProtectedConfigurationPurpose
{
    /// <summary>The prefix every configuration purpose starts with.</summary>
    public const string Prefix = "HkdfGuard.EncryptedConfiguration";

    // Purposes up to this many chars are built on the stack; longer ones in a pooled array.
    private const int MaxStackPurposeLength = 256;

    /// <summary>The purpose name for a configuration key - pass to KeyRing.CreateProtector.</summary>
    /// <param name="configurationKey">The full configuration path the value is stored under.</param>
    /// <exception cref="ArgumentException">configurationKey is null or empty</exception>
    public static string For(string configurationKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(configurationKey);

        return string.Create(Prefix.Length + 1 + configurationKey.Length, configurationKey,
            static (destination, key) => WritePurpose(key, destination));
    }

    /// <summary>
    /// The same purpose as UTF-8 bytes - the Additional Authenticated Data a value stored under
    /// <paramref name="configurationKey"/> is encrypted with (IPipelineDataProtector derives it
    /// from the secret identifier it's given; KeyRing protectors from <see cref="For"/>).
    /// </summary>
    /// <exception cref="ArgumentException">configurationKey is null or empty</exception>
    public static byte[] AadFor(string configurationKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(configurationKey);
        return AadFor(configurationKey.AsSpan());
    }

    /// <inheritdoc cref="AadFor(string)"/>
    public static byte[] AadFor(ReadOnlySpan<char> configurationKey)
    {
        if (configurationKey.IsEmpty)
            throw new ArgumentException("The configuration key must not be empty.", nameof(configurationKey));

        var length = Prefix.Length + 1 + configurationKey.Length;
        var rented = length > MaxStackPurposeLength ? ArrayPool<char>.Shared.Rent(length) : null;
        Span<char> buffer = rented is null ? stackalloc char[length] : rented.AsSpan(0, length);
        try
        {
            WritePurpose(configurationKey, buffer);
            var aad = new byte[Encoding.UTF8.GetByteCount(buffer)];
            Encoding.UTF8.GetBytes(buffer, aad);
            return aad;
        }
        finally
        {
            if (rented is not null)
                ArrayPool<char>.Shared.Return(rented);
        }
    }

    // Prefix + ':' + the key, with ASCII a-z upper-cased and everything else copied as-is.
    private static void WritePurpose(ReadOnlySpan<char> key, Span<char> destination)
    {
        Prefix.CopyTo(destination);
        destination[Prefix.Length] = ':';

        var canonical = destination[(Prefix.Length + 1)..];
        for (var i = 0; i < key.Length; i++)
            canonical[i] = char.IsAsciiLetterLower(key[i]) ? (char)(key[i] - ('a' - 'A')) : key[i];
    }
}
