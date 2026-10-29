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
/// <para>
/// To check what the secret holds, not just that it holds something, set
/// HKDFGUARD_TEST_AWS_SECRET_JSON to the JSON object its SecretString is expected to hold (a
/// key/value secret, as the console stores one): the whole value and each key, read as
/// "name#key", are then compared with it.
/// </para>
/// </summary>
public class AwsSecretsManagerSecretCacheIntegrationTests
{
    public const string SecretNameVariable = "HKDFGUARD_TEST_AWS_SECRET_NAME";
    public const string ExpectedJsonVariable = "HKDFGUARD_TEST_AWS_SECRET_JSON";

    private static System.Text.Json.Nodes.JsonObject Expected => TestHelpers.ExpectedSecret.Read(ExpectedJsonVariable)!;

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

    [AwsSecretsManagerJsonFact]
    public async Task Decrypt_RevealsTheExpectedWholeValue_AndEveryKey()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        TestHelpers.ExpectedSecret.AssertWholeValue(Expected, TestHelpers.ExpectedSecret.Decrypt(cache, SecretName));
        foreach (var (key, value) in TestHelpers.ExpectedSecret.Members(Expected))
            Assert.Equal(value, TestHelpers.ExpectedSecret.Decrypt(cache, $"{SecretName}#{key}"));
        Assert.Equal(0, cache.Decrypt($"{SecretName}#no-such-key", new byte[16]));
    }

    [AwsSecretsManagerJsonFact]
    public async Task DecryptAsync_RevealsEveryKey_AndTheExpectedWholeValue()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        foreach (var (key, value) in TestHelpers.ExpectedSecret.Members(Expected))
            Assert.Equal(value, await TestHelpers.ExpectedSecret.DecryptAsync(cache, $"{SecretName}#{key}"));
        TestHelpers.ExpectedSecret.AssertWholeValue(Expected, await TestHelpers.ExpectedSecret.DecryptAsync(cache, SecretName));
    }

    [AwsSecretsManagerFact]
    public async Task Decrypt_OfASecretThatDoesNotExist_ReturnsZero()
    {
        using var cache = new AwsSecretsManagerSecretCache(await TestHelpers.TestRing.CreateAsync());

        // Beside the configured secret, so a policy granting GetSecretValue on its path covers it:
        // without permission, Secrets Manager answers AccessDenied even for a secret that doesn't exist.
        var folder = SecretName.LastIndexOf('/') is var slash and >= 0 ? SecretName[..(slash + 1)] : "";
        Assert.Equal(0, cache.Decrypt($"{folder}hkdfguard-missing-{Guid.NewGuid():N}", new byte[16]));
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

/// <summary>
/// A real AWS Secrets Manager test that checks the secret's contents; reported as skipped unless
/// <see cref="AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable"/> and
/// <see cref="AwsSecretsManagerSecretCacheIntegrationTests.ExpectedJsonVariable"/> are set.
/// </summary>
public sealed class AwsSecretsManagerJsonFactAttribute : FactAttribute
{
    public AwsSecretsManagerJsonFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(AwsSecretsManagerSecretCacheIntegrationTests.ExpectedJsonVariable)))
            Skip = $"Set {AwsSecretsManagerSecretCacheIntegrationTests.SecretNameVariable} and {AwsSecretsManagerSecretCacheIntegrationTests.ExpectedJsonVariable} to check a secret's contents.";
    }
}
