namespace HkdfGuard.KeyWrapping.AwsKms.Test.TestHelpers;

/// <summary>The real KMS key the integration tests run against, if one was given.</summary>
public static class AwsKmsTestEnvironment
{
    public const string KeyIdVariable = "HKDFGUARD_TEST_AWS_KMS_KEY_ID";

    public static string? ConfiguredKeyId => Environment.GetEnvironmentVariable(KeyIdVariable) is { Length: > 0 } keyId ? keyId : null;

    public static string KeyId => ConfiguredKeyId
        ?? throw new InvalidOperationException($"{KeyIdVariable} is not set.");
}

/// <summary>
/// A test that makes real AWS KMS calls; reported as skipped unless
/// <see cref="AwsKmsTestEnvironment.KeyIdVariable"/> names a key. Once it does, a failing call is a
/// test failure, never a silent pass.
/// </summary>
public sealed class AwsKmsIntegrationFactAttribute : FactAttribute
{
    public AwsKmsIntegrationFactAttribute()
    {
        if (AwsKmsTestEnvironment.ConfiguredKeyId is null)
            Skip = $"Set {AwsKmsTestEnvironment.KeyIdVariable} to a symmetric KMS key to run AWS KMS integration tests.";
    }
}
