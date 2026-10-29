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
/// <para>
/// To check what the secret holds, not just that it holds something, set
/// HKDFGUARD_TEST_GOOGLE_SECRET_JSON to the JSON object its latest version's payload is expected to
/// hold: the whole value and each member, read as "id#key", are then compared with it.
/// </para>
/// </summary>
public class GoogleSecretManagerSecretCacheIntegrationTests
{
    public const string SecretNameVariable = "HKDFGUARD_TEST_GOOGLE_SECRET_NAME";
    public const string ExpectedJsonVariable = "HKDFGUARD_TEST_GOOGLE_SECRET_JSON";

    private static System.Text.Json.Nodes.JsonObject Expected => ExpectedSecret.Read(ExpectedJsonVariable)!;

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

    [GoogleSecretManagerJsonFact]
    public async Task Decrypt_RevealsTheExpectedWholeValue_AndEveryKey()
    {
        using var cache = await CreateAsync();

        ExpectedSecret.AssertWholeValue(Expected, ExpectedSecret.Decrypt(cache, Secret.SecretId));
        foreach (var (key, value) in ExpectedSecret.Members(Expected))
            Assert.Equal(value, ExpectedSecret.Decrypt(cache, $"{Secret.SecretId}#{key}"));
        Assert.Equal(0, cache.Decrypt($"{Secret.SecretId}#no-such-key", new byte[16]));
    }

    [GoogleSecretManagerJsonFact]
    public async Task DecryptAsync_RevealsEveryKey_AndTheExpectedWholeValue()
    {
        using var cache = await CreateAsync();

        foreach (var (key, value) in ExpectedSecret.Members(Expected))
            Assert.Equal(value, await ExpectedSecret.DecryptAsync(cache, $"{Secret.SecretId}#{key}"));
        ExpectedSecret.AssertWholeValue(Expected, await ExpectedSecret.DecryptAsync(cache, Secret.SecretId));
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

/// <summary>
/// A real Google Secret Manager test that checks the secret's contents; reported as skipped unless
/// <see cref="GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable"/> and
/// <see cref="GoogleSecretManagerSecretCacheIntegrationTests.ExpectedJsonVariable"/> are set.
/// </summary>
public sealed class GoogleSecretManagerJsonFactAttribute : FactAttribute
{
    public GoogleSecretManagerJsonFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(GoogleSecretManagerSecretCacheIntegrationTests.ExpectedJsonVariable)))
            Skip = $"Set {GoogleSecretManagerSecretCacheIntegrationTests.SecretNameVariable} and {GoogleSecretManagerSecretCacheIntegrationTests.ExpectedJsonVariable} to check a secret's contents.";
    }
}
