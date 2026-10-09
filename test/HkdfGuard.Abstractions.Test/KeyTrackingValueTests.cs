namespace HkdfGuard.Abstractions.Test;

public class KeyTrackingValueTests
{
    [Fact]
    public void Properties_HoldWhatTheyWereInitializedWith()
    {
        var value = new KeyTrackingValue { KeyVersion = 7, Value = [1, 2, 3] };

        Assert.Equal(7, value.KeyVersion);
        Assert.Equal([1, 2, 3], value.Value);
    }
}
