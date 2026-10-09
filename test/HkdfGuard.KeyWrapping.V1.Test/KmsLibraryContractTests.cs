using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class KmsLibraryContractTests
{
    [Fact]
    public void AbstractHkdfGuardKmsLibrary_Constants_MatchExpected()
    {
        Assert.Equal(32, AbstractHkdfGuardKmsLibrary.DekLength);
        Assert.Equal(0, AbstractHkdfGuardKmsLibrary.Ok);
    }

    [Fact]
    public void WindowsHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, WindowsHkdfGuardKmsLibrary.ErrInvalidArg);
        Assert.Equal(-2, WindowsHkdfGuardKmsLibrary.ErrBufferTooSmall);
        Assert.Equal(-3, WindowsHkdfGuardKmsLibrary.ErrProvider);
        Assert.Equal(-4, WindowsHkdfGuardKmsLibrary.ErrCrypto);
        Assert.Equal(-5, WindowsHkdfGuardKmsLibrary.ErrAuthFailed);
        Assert.Equal(-6, WindowsHkdfGuardKmsLibrary.ErrMalformed);
        Assert.Equal(-7, WindowsHkdfGuardKmsLibrary.ErrInternal);
        Assert.Equal(-8, WindowsHkdfGuardKmsLibrary.ErrServiceNameInvalid);
        Assert.Equal(-9, WindowsHkdfGuardKmsLibrary.ErrInvalidPolicy);
        Assert.Equal(-10, WindowsHkdfGuardKmsLibrary.ErrGroupInvalid);
        Assert.Equal(-11, WindowsHkdfGuardKmsLibrary.ErrKekMismatch);
        Assert.Equal(-12, WindowsHkdfGuardKmsLibrary.ErrKekNotFound);
        Assert.Equal(-13, WindowsHkdfGuardKmsLibrary.ErrAccessDenied);
        Assert.Equal(-14, WindowsHkdfGuardKmsLibrary.ErrKekAclInvalid);
    }

    [Fact]
    public void WindowsHkdfGuardKmsLibrary_DescribesEveryDefinedStatus_AndNothingElse()
    {
        var library = new WindowsHkdfGuardKmsLibrary();

        for (var status = -14; status <= -1; status++)
            Assert.False(string.IsNullOrEmpty(library.DescribeStatus(status)), $"no description for {status}");

        Assert.Null(library.DescribeStatus(-15));
        Assert.Null(library.DescribeStatus(1));
        Assert.Contains("not authorized", library.DescribeStatus(WindowsHkdfGuardKmsLibrary.ErrAccessDenied));
        Assert.Contains("HkdfGuardUsers", library.DescribeStatus(WindowsHkdfGuardKmsLibrary.ErrAccessDenied));
        Assert.Contains("provision", library.DescribeStatus(WindowsHkdfGuardKmsLibrary.ErrKekNotFound));
    }

    [Fact]
    public void MacOsHkdfGuardKmsLibrary_DescribesEveryReturnedStatus_ButNotTheReservedOnes()
    {
        var library = new MacOsHkdfGuardKmsLibrary();

        foreach (var status in new[] { -1, -2, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18 })
            Assert.False(string.IsNullOrEmpty(library.DescribeStatus(status)), $"no description for {status}");

        Assert.Null(library.DescribeStatus(MacOsHkdfGuardKmsLibrary.ErrKeyUnavailable));      // reserved, never returned
        Assert.Null(library.DescribeStatus(MacOsHkdfGuardKmsLibrary.ErrPublicKeyUnavailable)); // reserved, never returned
        Assert.Null(library.DescribeStatus(-19));
    }

    [Fact]
    public void LinuxHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, LinuxHkdfGuardKmsLibrary.ErrInvalidArgument);
        Assert.Equal(-2, LinuxHkdfGuardKmsLibrary.ErrBufferTooSmall);
        Assert.Equal(-3, LinuxHkdfGuardKmsLibrary.ErrProviderUnavailable);
        Assert.Equal(-4, LinuxHkdfGuardKmsLibrary.ErrProviderError);
        Assert.Equal(-5, LinuxHkdfGuardKmsLibrary.ErrCryptoError);
        Assert.Equal(-6, LinuxHkdfGuardKmsLibrary.ErrInternalError);
        Assert.Equal(-7, LinuxHkdfGuardKmsLibrary.ErrInvalidUtf8);
        Assert.Equal(-8, LinuxHkdfGuardKmsLibrary.ErrMissingServiceName);
    }

    [Fact]
    public void MacOsHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, MacOsHkdfGuardKmsLibrary.ErrInvalidInputLength);
        Assert.Equal(-2, MacOsHkdfGuardKmsLibrary.ErrOutputBufferTooSmall);
        Assert.Equal(-3, MacOsHkdfGuardKmsLibrary.ErrKeyUnavailable);
        Assert.Equal(-4, MacOsHkdfGuardKmsLibrary.ErrPublicKeyUnavailable);
        Assert.Equal(-5, MacOsHkdfGuardKmsLibrary.ErrEncryptionFailed);
        Assert.Equal(-6, MacOsHkdfGuardKmsLibrary.ErrDecryptionFailed);
        Assert.Equal(-7, MacOsHkdfGuardKmsLibrary.ErrUnexpectedOutputLength);
        Assert.Equal(-8, MacOsHkdfGuardKmsLibrary.ErrInvalidServiceIdentifier);
        Assert.Equal(-9, MacOsHkdfGuardKmsLibrary.ErrEnclaveUnavailable);
        Assert.Equal(-10, MacOsHkdfGuardKmsLibrary.ErrKekNotFound);
        Assert.Equal(-11, MacOsHkdfGuardKmsLibrary.ErrKekCorrupted);
        Assert.Equal(-12, MacOsHkdfGuardKmsLibrary.ErrAccessControlCreationFailed);
        Assert.Equal(-13, MacOsHkdfGuardKmsLibrary.ErrKeyGenerationFailed);
        Assert.Equal(-14, MacOsHkdfGuardKmsLibrary.ErrKeychainWriteFailed);
        Assert.Equal(-15, MacOsHkdfGuardKmsLibrary.ErrKekVerificationFailed);
        Assert.Equal(-16, MacOsHkdfGuardKmsLibrary.ErrFingerprintMismatch);
        Assert.Equal(-17, MacOsHkdfGuardKmsLibrary.ErrKeychainAccessDenied);
        Assert.Equal(-18, MacOsHkdfGuardKmsLibrary.ErrKeychainReadFailed);
    }
}
