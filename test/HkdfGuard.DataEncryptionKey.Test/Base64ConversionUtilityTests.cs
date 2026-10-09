using HkdfGuard.DataEncryptionKey.Utilities;

namespace HkdfGuard.DataEncryptionKey.Test;

public class Base64ConversionUtilityTests
{
    [Theory]
    [InlineData("AAAA", true)]
    [InlineData("AAA=", true)]
    [InlineData("", true)]
    [InlineData("not valid base64!!!", false)]
    public void IsBase64_CharSpan_ValidatesCorrectly(string input, bool expected)
        => Assert.Equal(expected, Base64ConversionUtility.IsBase64(input.AsSpan()));

    [Fact]
    public void IsBase64_ByteSpan_ValidatesCorrectly()
    {
        Assert.True(Base64ConversionUtility.IsBase64("AAAA"u8.ToArray()));
        Assert.False(Base64ConversionUtility.IsBase64("!!!!"u8.ToArray()));
    }

    [Fact]
    public void GetBinaryLength_EmptyInput_ReturnsZero()
        => Assert.Equal(0, Base64ConversionUtility.GetBinaryLength(ReadOnlySpan<char>.Empty));

    [Theory]
    [InlineData("QQ==", 1)]
    [InlineData("QUI=", 2)]
    [InlineData("QUJD", 3)]
    public void GetBinaryLength_ComputesCorrectLength(string base64, int expectedLength)
        => Assert.Equal(expectedLength, Base64ConversionUtility.GetBinaryLength(base64.AsSpan()));

    [Fact]
    public void GetBinaryLength_NotMultipleOfFour_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => Base64ConversionUtility.GetBinaryLength("AAA".AsSpan()));

    [Fact]
    public void GetBase64Length_EmptyInput_ReturnsZero()
        => Assert.Equal(0, Base64ConversionUtility.GetBase64Length(ReadOnlySpan<byte>.Empty));

    [Theory]
    [InlineData(1, 4)]
    [InlineData(2, 4)]
    [InlineData(3, 4)]
    [InlineData(4, 8)]
    public void GetBase64Length_ComputesCorrectLength(int byteLength, int expectedCharLength)
        => Assert.Equal(expectedCharLength, Base64ConversionUtility.GetBase64Length(new byte[byteLength]));

    [Fact]
    public void ToBase64String_ThenFromBase64_RoundTrips()
    {
        var data = "hello world"u8.ToArray();
        var base64 = Base64ConversionUtility.ToBase64String(data);
        var destination = new byte[Base64ConversionUtility.GetBinaryLength(base64)];

        var written = Base64ConversionUtility.FromBase64(base64, destination);

        Assert.Equal(data.Length, written);
        Assert.Equal(data, destination);
    }

    [Fact]
    public void FromBase64_WithInvalidInput_ThrowsFormatException()
    {
        var destination = new byte[16];
        Assert.Throws<FormatException>(() => Base64ConversionUtility.FromBase64("not valid base64!!!".AsSpan(), destination));
    }

    [Fact]
    public void FromBase64_WithTooSmallDestination_ThrowsFormatException()
    {
        var destination = new byte[1];
        Assert.Throws<FormatException>(() => Base64ConversionUtility.FromBase64("QUJD".AsSpan(), destination));
    }

    [Fact]
    public void ToBase64Chars_ThenFromBase64_RoundTrips()
    {
        var data = "round trip"u8.ToArray();
        var destination = new char[Base64ConversionUtility.GetBase64Length(data)];

        var written = Base64ConversionUtility.ToBase64Chars(data, destination);

        Assert.Equal(destination.Length, written);

        var decoded = new byte[Base64ConversionUtility.GetBinaryLength(destination.AsSpan(0, written))];
        Base64ConversionUtility.FromBase64(destination.AsSpan(0, written), decoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void ToBase64Chars_WithTooSmallDestination_ThrowsArgumentException()
    {
        var data = "hello"u8.ToArray();
        var destination = new char[1];

        Assert.Throws<ArgumentException>(() => Base64ConversionUtility.ToBase64Chars(data, destination));
    }
}
