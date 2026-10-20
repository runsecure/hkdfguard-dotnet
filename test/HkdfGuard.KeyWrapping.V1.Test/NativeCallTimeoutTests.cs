using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;
using Xunit.Sdk;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// NativeTestEnvironment's bound on a native call, which on macOS turns a keychain dialog nobody
/// answers into a failure that says so rather than a hung run. The bound itself is checked on every
/// platform, with stand-in calls; only macOS applies it to the first real call.
/// </summary>
public class NativeCallTimeoutTests
{
    [Fact]
    public void ANativeCallThatReturns_GivesItsResult()
        => Assert.Equal(42, NativeTestEnvironment.WithinNativeCallTimeout("hkdfguard.helper.test", () => 42, TimeSpan.FromSeconds(30)));

    [Fact]
    public void ANativeCallThatThrows_ThrowsTheSameException()
        => Assert.Throws<InvalidOperationException>(() =>
            NativeTestEnvironment.WithinNativeCallTimeout<int>("hkdfguard.helper.test", () => throw new InvalidOperationException("thrown"), TimeSpan.FromSeconds(30)));

    [Fact]
    public void ANativeCallThatNeverReturns_FailsTheTest_ExplainingTheKeychainDialog()
    {
        using var release = new ManualResetEventSlim();
        try
        {
            var thrown = Assert.ThrowsAny<XunitException>(() =>
                NativeTestEnvironment.WithinNativeCallTimeout("hkdfguard.helper.test", () => release.Wait(TimeSpan.FromSeconds(30)), TimeSpan.FromMilliseconds(100)));

            Assert.Contains("'hkdfguard.helper.test'", thrown.Message);
            Assert.Contains("keychain", thrown.Message);
            Assert.Contains("Always Allow", thrown.Message);
        }
        finally
        {
            release.Set(); // let the abandoned call finish
        }
    }
}
