namespace HkdfGuard.Cache.AwsSecretsManager.Test;

/// <summary>
/// Real calls against a secret the caller provides. Credentials and region come from the AWS SDK's
/// default chain (environment, %USERPROFILE%\.aws\credentials and config, an instance role...):
/// <code>
/// aws configure
/// HKDFGUARD_TEST_AWS_SECRET_NAME=prod/my-secret \
/// dotnet test test/HkdfGuard.Cache.AwsSecretsManager.Test
/// </code>
/// Without the variable every test here is reported as skipped - never as passed. The principal
/// needs only secretsmanager:GetSecretValue on that secret (and kms:Decrypt on its key, if it isn't
/// the AWS managed one); the tests never list, create, alter or delete a secret.
/// </summary>
public class AwsSecretsManagerSecretCacheIntegrationTests
{
    public const string SecretNameVariable = "HKDFGUARD_TEST_AWS_SECRET_NAME";

    private static string SecretName => Environment.GetEnvironmentVariable(SecretNameVariable)!;

    [AwsSecretsManagerFact]
    public async Task Decrypt_RevealsTheSecret()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        Assert.True(cache.TryGetMaxDecryptedLength(SecretName, out var max));
        Assert.True(cache.Decrypt(SecretName, new byte[max]) > 0);
    }

    [AwsSecretsManagerFact]
    public async Task DecryptAsync_RevealsTheSecret()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        var max = await cache.GetMaxDecryptedLengthAsync(SecretName);
        Assert.True(max > 0);
        Assert.True(await cache.DecryptAsync(SecretName, new byte[max].AsMemory()) > 0);
    }

    [AwsSecretsManagerFact]
    public async Task Decrypt_OfASecretThatDoesNotExist_ReturnsZero()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        Assert.Equal(0, cache.Decrypt($"hkdfguard/missing-{Guid.NewGuid():N}", new byte[16]));
    }
}

/// <summary>
/// A test that makes real AWS Secrets Manager calls; reported as skipped unless
/// <see cref="AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable"/> is set.
/// </summary>
public sealed class AwsSecretsManagerFactAttribute : FactAttribute
{
    public AwsSecretsManagerFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable)))
            Skip = $"Set {AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable} to a secret's name to run AWS Secrets Manager cache integration tests.";
    }
}
