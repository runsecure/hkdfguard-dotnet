using System.Security.Cryptography;
using Google.Cloud.Kms.V1;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.GoogleKms.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.GoogleKms.Test;

/// <summary>
/// Real calls against a symmetric Cloud KMS key the caller provides. The client signs in with
/// Application Default Credentials (gcloud auth application-default login, or the attached
/// service account):
/// <code>
/// dotnet test test/HkdfGuard.KeyWrapping.GoogleKms.Test --settings google.runsettings
/// </code>
/// Without HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME every test here is reported as skipped - never as
/// passed. The principal needs roles/cloudkms.cryptoKeyEncrypterDecrypter on the key; the tests
/// never create, alter or destroy a key.
/// </summary>
public class GoogleKmsIntegrationTests
{
    private const string Context = "hkdfguard.integrationtest";

    [GoogleKmsIntegrationFact]
    public async Task WrapThenUnwrap_RoundTripsA32ByteDek()
    {
        var wrapper = await CreateWrapperAsync(Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.Equal(dek, revealed);
    }

    [GoogleKmsIntegrationFact]
    public async Task GenerateAndWrap_ProducesAWrappedDekThatReveals()
    {
        var wrapper = await CreateWrapperAsync(Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.False(revealed.All(b => b == 0));
    }

    [GoogleKmsIntegrationFact]
    public async Task Unwrap_UnderAnotherContext_IsRefused()
    {
        var wrapper = await CreateWrapperAsync(Context);
        var other = await CreateWrapperAsync("hkdfguard.integrationtest.other");

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await other.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [GoogleKmsIntegrationFact]
    public async Task Unwrap_WhenTampered_IsRefused()
    {
        var wrapper = await CreateWrapperAsync(Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        wrapped[length - 1] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    // The key name first: a placeholder left in google.runsettings is reported as that, not as
    // whatever creating the client fails with.
    private static async Task<GoogleKmsKeyWrapper> CreateWrapperAsync(string context)
    {
        var keyName = GoogleKmsTestEnvironment.KeyName;
        return new GoogleKmsKeyWrapper(await KeyManagementServiceClient.CreateAsync(), keyName, context);
    }
}
