using System.Security;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

// The decision only - no Windows calls - so it runs on every platform.
public class WindowsRevocationPolicyTests
{
    private const string Path = @"C:\Program Files\HkdfGuard\v1\HkdfGuard.dll";

    [Fact]
    public void ARevokedCertificate_RefusesTheLoad()
    {
        Assert.True(WindowsRevocationPolicy.Refuses(unchecked((int)0x800B010C))); // CERT_E_REVOKED

        var ex = Assert.Throws<SecurityException>(() => WindowsRevocationPolicy.Verify(Path, unchecked((int)0x800B010C)));
        Assert.Contains(Path, ex.Message);
        Assert.Contains("revoked", ex.Message);
    }

    [Theory]
    [InlineData(0)]                                // success: checked, not revoked
    [InlineData(unchecked((int)0x80092013))]       // CRYPT_E_REVOCATION_OFFLINE: servers unreachable
    [InlineData(unchecked((int)0x80092012))]       // CRYPT_E_NO_REVOCATION_CHECK: no revocation information
    [InlineData(unchecked((int)0x800B010E))]       // CERT_E_REVOCATION_FAILURE: status could not be determined
    [InlineData(unchecked((int)0x800B0101))]       // any other result (CERT_E_EXPIRED here)
    public void AnyOtherResult_LetsTheLoadContinue(int status)
    {
        Assert.False(WindowsRevocationPolicy.Refuses(status));
        WindowsRevocationPolicy.Verify(Path, status);
    }
}
