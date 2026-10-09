using HkdfGuard.Abstractions;

namespace HkdfGuard.Abstractions.Test;

public class ArrayUtilityPinnedTests
{
    [Fact]
    public void AllocatePinned_ReturnsAZeroedArrayOfTheRequestedLength_OnThePinnedHeap()
    {
        var bytes = ArrayUtility.AllocatePinned<byte>(32);
        var chars = ArrayUtility.AllocatePinned<char>(44);

        Assert.Equal(32, bytes.Length);
        Assert.Equal(44, chars.Length);
        Assert.All(bytes, b => Assert.Equal(0, b));
        Assert.All(chars, c => Assert.Equal('\0', c));

        // A small array on the Pinned Object Heap reports the oldest generation straight away; an
        // ordinary one starts in generation 0. There is no direct "is pinned" API.
        Assert.Equal(GC.MaxGeneration, GC.GetGeneration(bytes));
        Assert.Equal(GC.MaxGeneration, GC.GetGeneration(chars));
        Assert.Equal(0, GC.GetGeneration(new byte[32]));
    }

    [Fact]
    public void StackLimits_AreFourKibibytes_InBothUnits()
    {
        Assert.Equal(4096, ArrayUtility.MaxStackBytes);
        Assert.Equal(2048, ArrayUtility.MaxStackChars);
    }
}
