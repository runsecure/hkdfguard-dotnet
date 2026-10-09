using System.Globalization;
using HkdfGuard.DataEncryptionKey.Utilities;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey.FormatProvider;

/// <summary>
/// The <c>enc::v{version}::{base64}</c> wire format. Formatted values are capped at
/// <see cref="MaxEncryptedLength"/> characters (4096 by default, which leaves room for about 3 KB
/// of UTF-8 plaintext): Parse rejects anything longer before decoding it, so oversized input can't
/// force a large allocation ahead of any cryptographic check, and Format refuses to produce a value
/// Parse would then reject.
/// </summary>
public class DefaultFormatProvider : IEncryptedFormatProvider
{
    public const int DefaultMaxEncryptedLength = 4096;

    private const string EncPrefix = "enc";
    private const string Delimiter = "::";
    private const string VersionPrefix = "v";

    /// <param name="maxEncryptedLength">Longest formatted value, in characters, that Format will
    /// produce or Parse will accept.</param>
    /// <exception cref="ArgumentOutOfRangeException">maxEncryptedLength is not positive</exception>
    public DefaultFormatProvider(int maxEncryptedLength = DefaultMaxEncryptedLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEncryptedLength);
        MaxEncryptedLength = maxEncryptedLength;
    }

    /// <summary>Longest formatted value, in characters, that Format will produce or Parse will accept.</summary>
    public int MaxEncryptedLength { get; }

    public string Format(KeyTrackingValue value)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderFormat);

        try
        {
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(value.Value);

            if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
                HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderFormat,
                    (AttributeNames.KeyVersion, value.KeyVersion), (AttributeNames.ValueLength, value.Value.Length));

            var base64 = Base64ConversionUtility.ToBase64String(value.Value);
            var version = value.KeyVersion.ToString(CultureInfo.InvariantCulture);
            var length = EncPrefix.Length + Delimiter.Length * 2 + VersionPrefix.Length + version.Length
                         + Base64ConversionUtility.GetBase64Length(value.Value);
            if (length > MaxEncryptedLength)
                throw new ArgumentException(
                    $"The formatted value would be {length} characters, over the {MaxEncryptedLength}-character limit.", nameof(value));

            // Invariant culture: the version must read back identically on any machine/locale.
            return string.Create(CultureInfo.InvariantCulture, $"{EncPrefix}{Delimiter}{VersionPrefix}{value.KeyVersion}{Delimiter}{base64}");
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    public KeyTrackingValue Parse(ReadOnlySpan<char> encrypted)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderParse);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderParse,
                (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out var version, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            if (!Base64ConversionUtility.IsBase64(base64))
                throw new FormatException("Encrypted value is not valid base64.");

            var value = new byte[Base64ConversionUtility.GetBinaryLength(base64)];
            Base64ConversionUtility.FromBase64(base64, value);

            return new KeyTrackingValue
            {
                KeyVersion = version,
                Value = value
            };
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength,
                (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out _, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            return Base64ConversionUtility.IsBase64(base64)
                ? Base64ConversionUtility.GetBinaryLength(base64)
                : throw new FormatException("Encrypted value is not valid base64.");
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    // Shared by Parse and GetMaxDecryptedLength so both agree on exactly what counts as
    // well-formed - only GetMaxDecryptedLength skips the actual Base64 decode/allocation.
    private bool TryParseSegments(ReadOnlySpan<char> encrypted, out int version, out ReadOnlySpan<char> base64)
    {
        version = 0;
        base64 = default;

        if (encrypted.Length > MaxEncryptedLength)
            throw new FormatException(
                $"Encrypted value is {encrypted.Length} characters, over the {MaxEncryptedLength}-character limit.");

        var delimiter = Delimiter.AsSpan();

        var firstDelimiterIndex = encrypted.IndexOf(delimiter);
        if (firstDelimiterIndex < 0)
            return false;

        var afterPrefix = encrypted[(firstDelimiterIndex + delimiter.Length)..];
        var secondDelimiterIndex = afterPrefix.IndexOf(delimiter);
        if (secondDelimiterIndex < 0)
            return false;

        var prefix = encrypted[..firstDelimiterIndex];
        var versionSegment = afterPrefix[..secondDelimiterIndex];
        var base64Segment = afterPrefix[(secondDelimiterIndex + delimiter.Length)..];

        if (!prefix.SequenceEqual(EncPrefix) || !versionSegment.StartsWith(VersionPrefix))
            return false;

        // Only the canonical form Format writes: ASCII digits with an optional leading '-' - no
        // whitespace, '+', or culture-specific signs/digits.
        var digits = versionSegment[VersionPrefix.Length..];
        if (digits.StartsWith('+')
            || !int.TryParse(digits, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out version))
            return false;

        base64 = base64Segment;
        return true;
    }
}
