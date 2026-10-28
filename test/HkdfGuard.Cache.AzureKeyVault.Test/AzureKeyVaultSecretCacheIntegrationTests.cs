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
/// <para>
/// To check what the secret holds, not just that it holds something, set
/// HKDFGUARD_TEST_AZURE_SECRET_JSON to the JSON object it is expected to hold: the whole value and
/// each member, read as "name#key", are then compared with it. Set
/// HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true as well when the vault also holds each member as a
/// secret of its own, named by its key; those are then read and compared too.
/// </para>
/// </summary>
public class AzureKeyVaultSecretCacheIntegrationTests
{
    public const string SecretIdVariable = "HKDFGUARD_TEST_AZURE_SECRET_ID";
    public const string ExpectedJsonVariable = "HKDFGUARD_TEST_AZURE_SECRET_JSON";
    public const string SeparateSecretsVariable = "HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS";

    private static System.Text.Json.Nodes.JsonObject Expected => ExpectedSecret.Read(ExpectedJsonVariable)!;

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

    [AzureKeyVaultSecretJsonFact]
    public async Task Decrypt_RevealsTheExpectedWholeValue()
    {
        var cache = await CreateAsync();

        ExpectedSecret.AssertWholeValue(Expected, ExpectedSecret.Decrypt(cache, SecretId.Name));
    }

    [AzureKeyVaultSecretJsonFact]
    public async Task Decrypt_RevealsEveryKeyTheSecretHolds()
    {
        var cache = await CreateAsync();

        foreach (var (key, value) in ExpectedSecret.Members(Expected))
            Assert.Equal(value, ExpectedSecret.Decrypt(cache, $"{SecretId.Name}#{key}"));
        Assert.Equal(0, cache.Decrypt($"{SecretId.Name}#no-such-key", new byte[16]));
    }

    [AzureKeyVaultSecretJsonFact]
    public async Task DecryptAsync_RevealsEveryKeyTheSecretHolds_AndTheWholeValue()
    {
        var cache = await CreateAsync();

        foreach (var (key, value) in ExpectedSecret.Members(Expected))
            Assert.Equal(value, await ExpectedSecret.DecryptAsync(cache, $"{SecretId.Name}#{key}"));
        ExpectedSecret.AssertWholeValue(Expected, await ExpectedSecret.DecryptAsync(cache, SecretId.Name));
    }

    [AzureKeyVaultSeparateSecretsFact]
    public async Task EachKey_IsAlsoASecretOfItsOwn_HoldingTheSameValue()
    {
        var cache = await CreateAsync();

        foreach (var (key, value) in ExpectedSecret.Members(Expected))
        {
            Assert.True(AzureKeyVaultSecretCache.IsValidSecretName(key), $"'{key}' can't be a Key Vault secret name.");
            Assert.Equal(value, ExpectedSecret.Decrypt(cache, key));

            // Key Vault matches secret names ignoring case, so the cache does too.
            Assert.Equal(value, ExpectedSecret.Decrypt(cache, key.ToUpperInvariant()));
        }
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

/// <summary>
/// A real Azure Key Vault test that checks the secret's contents; reported as skipped unless
/// <see cref="AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable"/> and
/// <see cref="AzureKeyVaultSecretCacheIntegrationTests.ExpectedJsonVariable"/> are set.
/// </summary>
public class AzureKeyVaultSecretJsonFactAttribute : FactAttribute
{
    public AzureKeyVaultSecretJsonFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AzureKeyVaultSecretCacheIntegrationTests.ExpectedJsonVariable)))
            Skip = $"Set {AzureKeyVaultSecretCacheIntegrationTests.SecretIdVariable} and {AzureKeyVaultSecretCacheIntegrationTests.ExpectedJsonVariable} to check a secret's contents.";
    }
}

/// <summary>
/// A real Azure Key Vault test reading each expected key as a secret of its own; reported as
/// skipped unless <see cref="AzureKeyVaultSecretCacheIntegrationTests.SeparateSecretsVariable"/> is
/// true, as well as what <see cref="AzureKeyVaultSecretJsonFactAttribute"/> needs.
/// </summary>
public sealed class AzureKeyVaultSeparateSecretsFactAttribute : AzureKeyVaultSecretJsonFactAttribute
{
    public AzureKeyVaultSeparateSecretsFactAttribute()
    {
        if (Skip is null && !string.Equals(Environment.GetEnvironmentVariable(AzureKeyVaultSecretCacheIntegrationTests.SeparateSecretsVariable), "true", StringComparison.OrdinalIgnoreCase))
            Skip = $"Set {AzureKeyVaultSecretCacheIntegrationTests.SeparateSecretsVariable}=true when the vault holds each expected key as a secret of its own.";
    }
}
