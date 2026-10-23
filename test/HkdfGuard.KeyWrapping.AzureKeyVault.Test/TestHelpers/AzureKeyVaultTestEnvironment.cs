namespace HkdfGuard.KeyWrapping.AzureKeyVault.Test.TestHelpers;

/// <summary>The real Key Vault keys the integration tests run against, if they were given.</summary>
public static class AzureKeyVaultTestEnvironment
{
    public const string WrappingKeyVariable = "HKDFGUARD_TEST_AZURE_WRAP_KEY_ID";
    public const string SigningKeyVariable = "HKDFGUARD_TEST_AZURE_SIGN_KEY_ID";

    // Read as text: a value that isn't a URI (a placeholder left in azure.runsettings, say) must
    // fail the tests with a message, not break test discovery.
    public static string? ConfiguredWrappingKeyId => Read(WrappingKeyVariable);
    public static string? ConfiguredSigningKeyId => Read(SigningKeyVariable);

    public static Uri WrappingKeyId => KeyId(WrappingKeyVariable, ConfiguredWrappingKeyId);
    public static Uri SigningKeyId => KeyId(SigningKeyVariable, ConfiguredSigningKeyId);

    private static Uri KeyId(string variable, string? value)
    {
        if (value is null)
            throw new InvalidOperationException($"{variable} is not set.");
        if (!Uri.TryCreate(value, UriKind.Absolute, out var keyId) || value.Contains('[', StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"{variable} is '{value}', which isn't a key identifier. Replace the placeholders in azure.runsettings (docs/how-to/run-azure-key-vault-integration-tests.md, step 5).");
        return keyId;
    }

    private static string? Read(string variable)
        => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value ? value : null;
}

/// <summary>
/// A test that makes real Azure Key Vault calls; reported as skipped unless both
/// <see cref="AzureKeyVaultTestEnvironment.WrappingKeyVariable"/> and
/// <see cref="AzureKeyVaultTestEnvironment.SigningKeyVariable"/> are set. Once they are, a failing
/// call is a test failure, never a silent pass.
/// </summary>
public sealed class AzureKeyVaultIntegrationFactAttribute : FactAttribute
{
    public AzureKeyVaultIntegrationFactAttribute()
    {
        if (AzureKeyVaultTestEnvironment.ConfiguredWrappingKeyId is null || AzureKeyVaultTestEnvironment.ConfiguredSigningKeyId is null)
            Skip = $"Set {AzureKeyVaultTestEnvironment.WrappingKeyVariable} to an RSA key and {AzureKeyVaultTestEnvironment.SigningKeyVariable} to an EC P-256 key to run Azure Key Vault integration tests.";
    }
}
