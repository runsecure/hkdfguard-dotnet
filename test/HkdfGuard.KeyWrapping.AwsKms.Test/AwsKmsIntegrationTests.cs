using System.Security.Cryptography;
using Amazon.KeyManagementService;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.AwsKms.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.AwsKms.Test;

/// <summary>
/// Real calls against a symmetric AWS KMS key the caller provides. The SDK resolves credentials
/// and region the usual way (environment, profile, instance or task role):
/// <code>
/// HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:... AWS_REGION=us-east-1 dotnet test test/HkdfGuard.KeyWrapping.AwsKms.Test
/// </code>
/// Without HKDFGUARD_TEST_AWS_KMS_KEY_ID every test here is reported as skipped - never as passed.
/// The principal needs kms:Encrypt, kms:Decrypt and kms:GenerateDataKeyWithoutPlaintext on the key;
/// the tests never create, alter or schedule deletion of a key.
/// </summary>
public class AwsKmsIntegrationTests
{
    private static readonly Dictionary<string, string> Context = new() { ["purpose"] = "hkdfguard.integrationtest" };

    [AwsKmsIntegrationFact]
    public async Task WrapThenUnwrap_RoundTripsA32ByteDek()
    {
        using var client = new AmazonKeyManagementServiceClient();
        var wrapper = new AwsKmsKeyWrapper(client, AwsKmsTestEnvironment.KeyId, Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.Equal(dek, revealed);
    }

    [AwsKmsIntegrationFact]
    public async Task GenerateAndWrap_ProducesAWrappedDekThatReveals()
    {
        using var client = new AmazonKeyManagementServiceClient();
        var wrapper = new AwsKmsKeyWrapper(client, AwsKmsTestEnvironment.KeyId, Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.False(revealed.All(b => b == 0));
    }

    [AwsKmsIntegrationFact]
    public async Task Unwrap_UnderAnotherContext_IsRefused()
    {
        using var client = new AmazonKeyManagementServiceClient();
        var wrapper = new AwsKmsKeyWrapper(client, AwsKmsTestEnvironment.KeyId, Context);
        var other = new AwsKmsKeyWrapper(client, AwsKmsTestEnvironment.KeyId,
            new Dictionary<string, string> { ["purpose"] = "hkdfguard.integrationtest.other" });

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await other.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [AwsKmsIntegrationFact]
    public async Task Unwrap_WhenTampered_IsRefused()
    {
        using var client = new AmazonKeyManagementServiceClient();
        var wrapper = new AwsKmsKeyWrapper(client, AwsKmsTestEnvironment.KeyId, Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        wrapped[length - 1] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }
}
