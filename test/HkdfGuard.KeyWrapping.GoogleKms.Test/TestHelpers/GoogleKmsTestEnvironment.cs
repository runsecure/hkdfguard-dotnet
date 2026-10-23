using Google.Cloud.Kms.V1;

namespace HkdfGuard.KeyWrapping.GoogleKms.Test.TestHelpers;

/// <summary>The real Cloud KMS key the integration tests run against, if one was given.</summary>
public static class GoogleKmsTestEnvironment
{
    public const string KeyNameVariable = "HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME";

    // Read as text: a value that isn't a key name (a placeholder left in google.runsettings, say)
    // must fail the tests with a message, not break test discovery.
    public static string? ConfiguredKeyName => Environment.GetEnvironmentVariable(KeyNameVariable) is { Length: > 0 } value ? value : null;

    public static string KeyName
    {
        get
        {
            var value = ConfiguredKeyName ?? throw new InvalidOperationException($"{KeyNameVariable} is not set.");
            if (value.Contains('[', StringComparison.Ordinal) || !CryptoKeyName.TryParse(value, out _))
                throw new InvalidOperationException(
                    $"{KeyNameVariable} is '{value}', which isn't a key's resource name. Replace the placeholders in google.runsettings (docs/how-to/run-google-kms-integration-tests.md, step 5).");
            return value;
        }
    }
}

/// <summary>
/// A test that makes real Cloud KMS calls; reported as skipped unless
/// <see cref="GoogleKmsTestEnvironment.KeyNameVariable"/> names a key. Once it does, a failing call
/// is a test failure, never a silent pass.
/// </summary>
public sealed class GoogleKmsIntegrationFactAttribute : FactAttribute
{
    public GoogleKmsIntegrationFactAttribute()
    {
        if (GoogleKmsTestEnvironment.ConfiguredKeyName is null)
            Skip = $"Set {GoogleKmsTestEnvironment.KeyNameVariable} to a symmetric Cloud KMS key to run Cloud KMS integration tests.";
    }
}
