using System.Security.Cryptography;
using Azure.Identity;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.AzureKeyVault.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.AzureKeyVault.Test;

/// <summary>
/// Real calls against an RSA wrapping key and an EC P-256 signing key the caller provides. Credentials
/// come from DefaultAzureCredential (environment, managed identity, Azure CLI, Visual Studio...):
/// <code>
/// az login
/// HKDFGUARD_TEST_AZURE_WRAP_KEY_ID=https://{vault}.vault.azure.net/keys/{rsa-key} \
/// HKDFGUARD_TEST_AZURE_SIGN_KEY_ID=https://{vault}.vault.azure.net/keys/{ec-key} \
/// dotnet test test/HkdfGuard.KeyWrapping.AzureKeyVault.Test
/// </code>
/// Without both variables every test here is reported as skipped - never as passed. The principal
/// needs wrapKey and unwrapKey on the RSA key, and sign and verify on the EC key (the Key Vault
/// Crypto User role on each); the tests never create, alter or delete a key.
/// </summary>
public class AzureKeyVaultIntegrationTests
{
    private const string Context = "hkdfguard.integrationtest";

    private static AzureKeyVaultKeyWrapper Wrapper(string context = Context)
        => new(AzureKeyVaultTestEnvironment.WrappingKeyId, AzureKeyVaultTestEnvironment.SigningKeyId, new DefaultAzureCredential(), context);

    [AzureKeyVaultIntegrationFact]
    public async Task WrapThenUnwrap_RoundTripsA32ByteDek()
    {
        var wrapper = Wrapper();
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.Equal(dek, revealed);
    }

    [AzureKeyVaultIntegrationFact]
    public async Task GenerateAndWrap_ProducesAWrappedDekThatReveals()
    {
        var wrapper = Wrapper();

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.False(revealed.All(b => b == 0));
    }

    [AzureKeyVaultIntegrationFact]
    public async Task Unwrap_UnderAnotherContext_IsRefused()
    {
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await Wrapper().GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await Wrapper("hkdfguard.integrationtest.other").UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [AzureKeyVaultIntegrationFact]
    public async Task Unwrap_WhenTampered_IsRefused()
    {
        var wrapper = Wrapper();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        wrapped[WrappedDekEnvelope.HeaderLength + 10] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }
}
