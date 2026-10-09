using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// A bad service name is rejected at construction, so it can never reach native code.
/// </summary>
public class ServiceNameValidationTests
{
    [Theory]
    [InlineData("")]
    [InlineData(".service")]
    [InlineData("my..service")]
    [InlineData("my-service")]
    public void Constructor_RejectsAnInvalidName_BeforeAnyNativeCall(string serviceName)
    {
        var library = new FakeHkdfGuardKmsLibrary();

        Assert.Throws<ArgumentException>(() => new NativeHkdfKeyWrapperV1(serviceName, library));

        Assert.Equal(0, library.WrapCallCount + library.UnwrapCallCount + library.GenerateAndWrapCallCount);
    }

    [Fact]
    public void Constructor_RejectsANullName()
    {
        Assert.Throws<ArgumentNullException>(() => new NativeHkdfKeyWrapperV1(null!, new FakeHkdfGuardKmsLibrary()));
    }

    [Fact]
    public void Constructor_RejectsAnOverlongName()
    {
        Assert.Throws<ArgumentException>(() => new NativeHkdfKeyWrapperV1(new string('a', 129), new FakeHkdfGuardKmsLibrary()));
    }
}
