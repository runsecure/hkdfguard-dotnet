using System.Globalization;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class DefaultFormatProviderTests
{
    private readonly DefaultFormatProvider _provider = new();

    [Fact]
    public void FormatParseGetMaxDecryptedLength_WithSensitiveLoggingEnabled_StillWorkCorrectly()
    {
        using var _ = new SensitiveLoggingScope(true);

        var value = new KeyTrackingValue { KeyVersion = 2, Value = "abc"u8.ToArray() };
        var formatted = _provider.Format(value);
        var parsed = _provider.Parse(formatted.AsSpan());
        var maxLength = _provider.GetMaxDecryptedLength(formatted.AsSpan());

        Assert.Equal(value.Value, parsed.Value);
        Assert.Equal(parsed.Value.Length, maxLength);
    }

    [Fact]
    public void FormatThenParse_RoundTrips()
    {
        var value = new KeyTrackingValue { KeyVersion = 7, Value = "hello"u8.ToArray() };

        var formatted = _provider.Format(value);
        Assert.StartsWith("enc::v7::", formatted);

        var parsed = _provider.Parse(formatted.AsSpan());
        Assert.Equal(7, parsed.KeyVersion);
        Assert.Equal(value.Value, parsed.Value);
    }

    [Fact]
    public void Format_WithEmptyValue_RoundTrips()
    {
        var value = new KeyTrackingValue { KeyVersion = 1, Value = [] };

        var formatted = _provider.Format(value);
        var parsed = _provider.Parse(formatted.AsSpan());

        Assert.Equal(1, parsed.KeyVersion);
        Assert.Empty(parsed.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-delimiters-at-all")]
    [InlineData("enc::onlyonepart")]
    [InlineData("wrong::v1::AAAA")]
    [InlineData("enc::1::AAAA")]
    [InlineData("enc::vNotANumber::AAAA")]
    public void Parse_WithMalformedInput_ThrowsFormatException(string input)
        => Assert.Throws<FormatException>(() => _provider.Parse(input.AsSpan()));

    [Fact]
    public void Parse_WithInvalidBase64_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => _provider.Parse("enc::v1::not-valid-base64!!!".AsSpan()));

    [Fact]
    public void GetMaxDecryptedLength_MatchesParsedValueLength()
    {
        var value = new KeyTrackingValue { KeyVersion = 3, Value = RandomNumberGenerator.GetBytes(40) };
        var formatted = _provider.Format(value);

        var maxLength = _provider.GetMaxDecryptedLength(formatted.AsSpan());
        var parsed = _provider.Parse(formatted.AsSpan());

        Assert.Equal(parsed.Value.Length, maxLength);
    }

    [Theory]
    [InlineData("")]
    [InlineData("enc::onlyonepart")]
    [InlineData("enc::1::AAAA")]
    public void GetMaxDecryptedLength_WithMalformedInput_ThrowsFormatException(string input)
        => Assert.Throws<FormatException>(() => _provider.GetMaxDecryptedLength(input.AsSpan()));

    [Fact]
    public void GetMaxDecryptedLength_WithInvalidBase64_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => _provider.GetMaxDecryptedLength("enc::v1::not-valid-base64!!!".AsSpan()));

    // A culture whose negative sign isn't '-' - deterministic on every machine, unlike real
    // cultures whose formatting depends on the installed ICU data.
    private static CultureInfo TildeNegativeCulture()
    {
        var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        culture.NumberFormat.NegativeSign = "~";
        return culture;
    }

    private static T WithCurrentCulture<T>(CultureInfo culture, Func<T> action)
    {
        var original = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = culture;
        try
        {
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    [Fact]
    public void Format_UsesTheInvariantCultureRegardlessOfTheCurrentCulture()
    {
        var formatted = WithCurrentCulture(TildeNegativeCulture(), () =>
            _provider.Format(new KeyTrackingValue { KeyVersion = -5, Value = [1, 2, 3] }));

        Assert.StartsWith("enc::v-5::", formatted);
    }

    [Fact]
    public void FormatThenParse_RoundTripsANegativeVersionUnderAnyCulture()
    {
        var formatted = _provider.Format(new KeyTrackingValue { KeyVersion = -5, Value = [1, 2, 3] });

        var parsed = WithCurrentCulture(TildeNegativeCulture(), () => _provider.Parse(formatted));

        Assert.Equal(-5, parsed.KeyVersion);
    }

    [Theory]
    [InlineData("enc::v+1::AQID")]
    [InlineData("enc::v 1::AQID")]
    [InlineData("enc::v1 ::AQID")]
    [InlineData("enc::v~1::AQID")]
    [InlineData("enc::v::AQID")]
    public void Parse_RejectsVersionsThatAreNotInCanonicalForm(string encrypted)
    {
        WithCurrentCulture(TildeNegativeCulture(), () =>
            Assert.Throws<FormatException>(() => _provider.Parse(encrypted)));
    }

    [Fact]
    public void Format_WithANullValue_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _provider.Format(null!));
    }

    [Fact]
    public void Format_WithANullPayload_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _provider.Format(new KeyTrackingValue { KeyVersion = 1, Value = null! }));
    }

    // "enc::v1234::" is 12 characters, leaving exactly 4084 for base64 - which encodes 3063 bytes.
    private static KeyTrackingValue ValueFormattingTo(int extraBytes = 0)
        => new() { KeyVersion = 1234, Value = RandomNumberGenerator.GetBytes(3063 + extraBytes) };

    [Fact]
    public void MaxEncryptedLength_DefaultsTo4096()
    {
        Assert.Equal(4096, DefaultFormatProvider.DefaultMaxEncryptedLength);
        Assert.Equal(4096, new DefaultFormatProvider().MaxEncryptedLength);
    }

    [Fact]
    public void FormatAndParse_AValueOfExactlyTheLimit_RoundTrips()
    {
        var value = ValueFormattingTo();

        var formatted = _provider.Format(value);
        var parsed = _provider.Parse(formatted);

        Assert.Equal(4096, formatted.Length);
        Assert.Equal(value.Value, parsed.Value);
        Assert.Equal(3063, _provider.GetMaxDecryptedLength(formatted));
    }

    [Fact]
    public void Format_AValueOverTheLimit_IsRefusedRatherThanWrittenUnreadable()
    {
        var exception = Assert.Throws<ArgumentException>(() => _provider.Format(ValueFormattingTo(extraBytes: 1)));

        Assert.Contains("4096", exception.Message);
    }

    [Fact]
    public void ParseAndGetMaxDecryptedLength_InputOverTheLimit_AreRejectedBeforeDecoding()
    {
        // Well-formed apart from its length: one base64 quantum past the limit.
        var tooLong = "enc::v1234::" + new string('A', 4088);

        Assert.Throws<FormatException>(() => _provider.Parse(tooLong));
        Assert.Throws<FormatException>(() => _provider.GetMaxDecryptedLength(tooLong));
    }

    [Fact]
    public void ACustomLimit_AppliesToFormatAndParse()
    {
        var provider = new DefaultFormatProvider(maxEncryptedLength: 64);
        var fits = new KeyTrackingValue { KeyVersion = 1, Value = new byte[40] };       // 9 + 56 = 65 > 64
        var smaller = new KeyTrackingValue { KeyVersion = 1, Value = new byte[39] };    // 9 + 52 = 61

        Assert.Throws<ArgumentException>(() => provider.Format(fits));
        Assert.Equal(39, provider.Parse(provider.Format(smaller)).Value.Length);
        Assert.Throws<FormatException>(() => provider.Parse(_provider.Format(fits)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_WithANonPositiveLimit_Throws(int maxEncryptedLength)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DefaultFormatProvider(maxEncryptedLength));
    }
}
