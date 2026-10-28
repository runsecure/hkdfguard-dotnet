using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using HkdfGuard.Cache.AzureKeyVault.Test.TestHelpers;

namespace HkdfGuard.Cache.AzureKeyVault.Test;

/// <summary>
/// Real calls against a secret the caller provides. Credentials come from DefaultAzureCredential
/// (environment, managed identity, Azure CLI, Visual Studio...):
/// <code>
/// az login
/// HKDFGUARD_TEST_AZURE_SECRET_ID=https://{vault}.vault.azure.net/secrets/{name} \
/// dotnet test test/HkdfGuard.Cache.AzureKeyVault.Test
/// </code>
/// Without the variable every test here is reported as skipped - never as passed. The principal
/// needs only get on secrets (the Key Vault Secrets User role); the tests never list, create, alter
/// or delete a secret.
/// </summary>
public class AzureKeyVaultSecretCacheIntegrationTests
{
    public const string SecretIdVariable = "HKDFGUARD_TEST_AZURE_SECRET_ID";

    private static KeyVaultSecretIdentifier SecretId
        => new(new Uri(Environment.GetEnvironmentVariable(SecretIdVariable)!));

    private static async Task<AzureKeyVaultSecretCache> CreateAsync()
        => new(SecretId.VaultUri, new DefaultAzureCredential(), await TestRing.CreateAsync());

    [AzureKeyVaultSecretFact]
    public async Task Decrypt_RevealsTheSecret()
    {
        var cache = await CreateAsync();

        Assert.True(cache.TryGetMaxDecryptedLength(SecretId.Name, out var max));
        Assert.True(cache.Decrypt(SecretId.Name, new char[max].AsSpan()) > 0);
    }

    [AzureKeyVaultSecretFact]
    public async Task DecryptAsync_RevealsTheSecret()
    {
        var cache = await CreateAsync();

        var max = await cache.GetMaxDecryptedLengthAsync(SecretId.Name);
        Assert.True(max > 0);
        Assert.True(await cache.DecryptAsync(SecretId.Name, new char[max].AsMemory()) > 0);
    }

    [AzureKeyVaultSecretFact]
    public async Task Decrypt_OfASecretThatDoesNotExist_ReturnsZero()
    {
        var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt($"hkdfguard-missing-{Guid.NewGuid():N}", new byte[16]));
    }
}

/// <summary>
/// A test that makes real Azure Key Vault calls; reported as skipped unless
/// <see cref="AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable"/> is set.
/// </summary>
public sealed class AzureKeyVaultSecretFactAttribute : FactAttribute
{
    public AzureKeyVaultSecretFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable)))
            Skip = $"Set {AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable} to a secret's identifier to run Azure Key Vault secret cache integration tests.";
    }
}
