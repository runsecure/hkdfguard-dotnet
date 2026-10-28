using Google.Apis.Auth.OAuth2;
using Google.Cloud.SecretManager.V1;
using HkdfGuard.Cache.GoogleSecretManager.Test.TestHelpers;

namespace HkdfGuard.Cache.GoogleSecretManager.Test;

/// <summary>
/// Real calls against a secret the caller provides. Credentials come from Application Default
/// Credentials (gcloud auth application-default login, a service account, the metadata server...):
/// <code>
/// gcloud auth application-default login
/// HKDFGUARD_TEST_GOOGLE_SECRET_NAME=projects/{project}/secrets/{secret} \
/// dotnet test test/HkdfGuard.Cache.GoogleSecretManager.Test
/// </code>
/// Without the variable every test here is reported as skipped - never as passed. The principal
/// needs only secretmanager.versions.access on that secret (the Secret Manager Secret Accessor
/// role); the tests never list, create, alter or delete a secret.
/// </summary>
public class GoogleSecretManagerSecretCacheIntegrationTests
{
    public const string SecretNameVariable = "HKDFGUARD_TEST_GOOGLE_SECRET_NAME";

    private static SecretName Secret => SecretName.Parse(Environment.GetEnvironmentVariable(SecretNameVariable)!);

    private static async Task<GoogleSecretManagerSecretCache> CreateAsync()
        => GoogleSecretManagerSecretCache.Create(Secret.ProjectId, await GoogleCredential.GetApplicationDefaultAsync(), await TestRing.CreateAsync());

    [GoogleSecretManagerFact]
    public async Task Decrypt_RevealsTheSecret()
    {
        using var cache = await CreateAsync();

        Assert.True(cache.TryGetMaxDecryptedLength(Secret.SecretId, out var max));
        Assert.True(cache.Decrypt(Secret.SecretId, new byte[max]) > 0);
    }

    [GoogleSecretManagerFact]
    public async Task DecryptAsync_RevealsTheSecret()
    {
        using var cache = await CreateAsync();

        var max = await cache.GetMaxDecryptedLengthAsync(Secret.SecretId);
        Assert.True(max > 0);
        Assert.True(await cache.DecryptAsync(Secret.SecretId, new byte[max].AsMemory()) > 0);
    }

    [GoogleSecretManagerFact]
    public async Task Decrypt_OfASecretThatDoesNotExist_ReturnsZero()
    {
        using var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt($"hkdfguard-missing-{Guid.NewGuid():N}", new byte[16]));
    }
}

/// <summary>
/// A test that makes real Google Cloud Secret Manager calls; reported as skipped unless
/// <see cref="GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable"/> is set.
/// </summary>
public sealed class GoogleSecretManagerFactAttribute : FactAttribute
{
    public GoogleSecretManagerFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable)))
            Skip = $"Set {GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable} to a secret's resource name to run Google Secret Manager cache integration tests.";
    }
}
