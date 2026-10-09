using HkdfGuard.Abstractions;

namespace HkdfGuard.Abstractions.Test;

public class ArrayUtilityTests
{
    [Fact]
    public void IsNullOrEmpty_Bytes_WithAllZeroSpan_ReturnsTrue()
    {
        Assert.True(ArrayUtility.IsNullOrEmpty(new byte[16]));
    }

    [Fact]
    public void IsNullOrEmpty_Bytes_WithEmptySpan_ReturnsTrue()
    {
        Assert.True(ArrayUtility.IsNullOrEmpty(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void IsNullOrEmpty_Bytes_WithNonZeroByte_ReturnsFalse()
    {
        var bytes = new byte[16];
        bytes[10] = 1;

        Assert.False(ArrayUtility.IsNullOrEmpty(bytes));
    }

    [Fact]
    public void IsNullOrEmpty_Chars_WithAllZeroSpan_ReturnsTrue()
    {
        Assert.True(ArrayUtility.IsNullOrEmpty(new char[16]));
    }

    [Fact]
    public void IsNullOrEmpty_Chars_WithEmptySpan_ReturnsTrue()
    {
        Assert.True(ArrayUtility.IsNullOrEmpty(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void IsNullOrEmpty_Chars_WithNonZeroChar_ReturnsFalse()
    {
        var chars = new char[16];
        chars[3] = 'a';

        Assert.False(ArrayUtility.IsNullOrEmpty(chars));
    }

    [Fact]
    public void ZeroMemory_Bytes_ClearsEveryByte()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };

        ArrayUtility.ZeroMemory(bytes);

        Assert.Equal(new byte[5], bytes);
    }

    [Fact]
    public void ZeroMemory_Bytes_WithEmptySpan_DoesNotThrow()
    {
        var exception = Record.Exception(() => ArrayUtility.ZeroMemory(Span<byte>.Empty));

        Assert.Null(exception);
    }

    [Fact]
    public void ZeroMemory_Chars_ClearsEveryChar()
    {
        var chars = "hello".ToCharArray();

        ArrayUtility.ZeroMemory(chars);

        Assert.Equal(new char[5], chars);
    }

    [Fact]
    public void ZeroMemory_Chars_WithEmptySpan_DoesNotThrow()
    {
        var exception = Record.Exception(() => ArrayUtility.ZeroMemory(Span<char>.Empty));

        Assert.Null(exception);
    }

    [Fact]
    public void IsNullOrEmpty_WithTheOnlyNonZeroAtTheEnd_ReturnsFalseForBothOverloads()
    {
        var bytes = new byte[64];
        bytes[^1] = 1;
        var chars = new char[64];
        chars[^1] = '\u0100';

        Assert.False(ArrayUtility.IsNullOrEmpty(bytes));
        Assert.False(ArrayUtility.IsNullOrEmpty(chars));
    }
}
