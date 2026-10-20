using System.Net;
using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.KeyWrapping.AwsKms.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.AwsKms.Test;

public class AwsKmsKeyWrapperTests
{
    private const string KeyArn = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    private static readonly Dictionary<string, string> Context = new() { ["purpose"] = "hkdfguard.test" };

    [Fact]
    public void Constructor_RejectsMissingArguments()
    {
        var kms = FakeKms.Create();

        Assert.Throws<ArgumentNullException>(() => new AwsKmsKeyWrapper(null!, KeyArn));
        Assert.Throws<ArgumentNullException>(() => new AwsKmsKeyWrapper(kms.Client, null!));
        Assert.Throws<ArgumentException>(() => new AwsKmsKeyWrapper(kms.Client, " "));
        Assert.Throws<ArgumentException>(() => new AwsKmsKeyWrapper(kms.Client, KeyArn, new Dictionary<string, string> { [""] = "x" }));
        Assert.Throws<ArgumentNullException>(() => new AwsKmsKeyWrapper(kms.Client, KeyArn, new Dictionary<string, string> { ["k"] = null! }));
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTripsTheDek()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn, Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var wrappedLength = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];
        var revealedLength = await wrapper.UnwrapAsync(wrapped.AsMemory(0, wrappedLength), revealed);

        Assert.Equal(32, revealedLength);
        Assert.Equal(dek, revealed);
    }

    [Fact]
    public async Task WrapAsync_SendsTheKeyContextAndAlgorithm_AndZeroesItsCopyOfThePlaintext()
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn, Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        await wrapper.WrapAsync(dek, new byte[WrappedKeyLimits.MaxBytes]);

        var request = Assert.Single(kms.EncryptRequests);
        Assert.Equal(KeyArn, request.KeyId);
        Assert.Equal(Context, request.EncryptionContext);
        Assert.Equal(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT, request.EncryptionAlgorithm);
        Assert.Equal(dek, kms.EncryptPlaintexts[0]);
        Assert.All(request.Plaintext.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task WithNoContext_SendsNone()
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn, new Dictionary<string, string>());

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]);

        Assert.Null(kms.GenerateRequests[0].EncryptionContext);
        Assert.Null(kms.DecryptRequests[0].EncryptionContext);
    }

    [Fact]
    public async Task TheContextIsCopied_AtConstructionAndPerRequest()
    {
        var kms = FakeKms.Create();
        var context = new Dictionary<string, string>(Context);
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn, context);
        context["purpose"] = "changed";

        await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]);
        kms.GenerateRequests[0].EncryptionContext["purpose"] = "changed by the pipeline";
        await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]);

        Assert.Equal("hkdfguard.test", kms.GenerateRequests[1].EncryptionContext["purpose"]);
    }

    [Fact]
    public async Task GenerateAndWrapAsync_AsksKmsForAWrappedAes256KeyOnly()
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn, Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];
        var revealedLength = await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed);

        var request = Assert.Single(kms.GenerateRequests);
        Assert.Equal(KeyArn, request.KeyId);
        Assert.Equal(DataKeySpec.AES_256, request.KeySpec);
        Assert.Equal(Context, request.EncryptionContext);
        Assert.Empty(kms.EncryptRequests);
        Assert.Equal(AwsKmsKeyWrapper.GeneratedKeyLength, revealedLength);
        Assert.False(revealed.All(b => b == 0));
    }

    [Fact]
    public async Task UnwrapAsync_PinsTheKey_AndZeroesTheRevealedStream()
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn, Context);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]);

        var request = Assert.Single(kms.DecryptRequests);
        Assert.Equal(KeyArn, request.KeyId);
        Assert.Equal(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT, request.EncryptionAlgorithm);
        Assert.Equal(wrapped[..length], request.CiphertextBlob.ToArray());
        Assert.All(kms.DecryptPlaintextStreams[0].ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherKey_FailsAndZeroesTheResult()
    {
        var kms = FakeKms.Create();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new AwsKmsKeyWrapper(kms.Client, "alias/other", Context)
            .WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        var result = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new AwsKmsKeyWrapper(kms.Client, KeyArn, Context).UnwrapAsync(wrapped.AsMemory(0, length), result));

        Assert.IsType<InvalidCiphertextException>(exception.InnerException);
        Assert.Equal($"AWS KMS unwrap failed for key '{KeyArn}': InvalidCiphertextException (HTTP 400).", exception.Message);
        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherContext_Fails()
    {
        var kms = FakeKms.Create();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new AwsKmsKeyWrapper(kms.Client, KeyArn, Context).WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);
        var other = new AwsKmsKeyWrapper(kms.Client, KeyArn, new Dictionary<string, string> { ["purpose"] = "other" });

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await other.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [Fact]
    public async Task UnwrapAsync_WhenTampered_Fails()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn, Context);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);
        wrapped[length - 1] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(WrappedKeyLimits.MaxBytes + 1)]
    public async Task UnwrapAsync_OutOfBounds_FailsWithoutCallingKms(int size)
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[size], new byte[32]));

        Assert.Empty(kms.DecryptRequests);
    }

    [Fact]
    public async Task UnwrapAsync_WhenTheKeyDoesNotFit_FailsZeroesTheResultAndScrubsTheStream()
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        var result = Enumerable.Repeat((byte)0xAA, 16).ToArray();
        await Assert.ThrowsAsync<ArgumentException>("result", async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), result));

        Assert.All(result, b => Assert.Equal(0, b));
        Assert.All(kms.DecryptPlaintextStreams[0].ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_WhenKmsReturnsNoPlaintext_Fails()
    {
        var kms = FakeKms.Create();
        kms.OnDecrypt = _ => new DecryptResponse();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[64], new byte[32]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(AwsKmsKeyWrapper.MaxPlaintextLength + 1)]
    public async Task WrapAsync_RejectsAPlaintextKmsWouldRefuse(int size)
    {
        var kms = FakeKms.Create();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        await Assert.ThrowsAsync<ArgumentException>("plaintext", async () =>
            await wrapper.WrapAsync(new byte[size], new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Empty(kms.EncryptRequests);
    }

    [Fact]
    public async Task WrapAsync_WhenResultIsTooSmall_Throws()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn);

        await Assert.ThrowsAsync<ArgumentException>("result", async () =>
            await wrapper.WrapAsync(new byte[32], new byte[8]));
    }

    [Fact]
    public async Task GenerateAndWrapAsync_RefusesACiphertextOverTheKeyFileLimit()
    {
        var kms = FakeKms.Create();
        kms.OnGenerate = _ => new GenerateDataKeyWithoutPlaintextResponse
        {
            CiphertextBlob = new MemoryStream(new byte[WrappedKeyLimits.MaxBytes + 1]),
        };
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[2 * WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public async Task GenerateAndWrapAsync_WhenKmsReturnsNoCiphertext_Fails()
    {
        var kms = FakeKms.Create();
        kms.OnGenerate = _ => new GenerateDataKeyWithoutPlaintextResponse();
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public async Task AServiceRefusal_BecomesACryptographicExceptionNamingTheErrorCode()
    {
        var kms = FakeKms.Create();
        kms.OnEncrypt = _ => throw FakeKms.ServiceError<AmazonKeyManagementServiceException>("AccessDeniedException");
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.WrapAsync(new byte[32], new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Equal($"AWS KMS wrap failed for key '{KeyArn}': AccessDeniedException (HTTP 400).", exception.Message);
        Assert.IsType<AmazonKeyManagementServiceException>(exception.InnerException);
    }

    [Fact]
    public async Task AServiceRefusalWithNoErrorCode_IsNamedByItsType()
    {
        var kms = FakeKms.Create();
        kms.OnDecrypt = _ => throw FakeKms.ServiceError<KMSInternalException>(null!, HttpStatusCode.InternalServerError);
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[64], new byte[32]));

        Assert.Equal($"AWS KMS unwrap failed for key '{KeyArn}': KMSInternalException (HTTP 500).", exception.Message);
    }

    [Fact]
    public async Task AClientSideFailure_BecomesACryptographicException()
    {
        var kms = FakeKms.Create();
        kms.OnGenerate = _ => throw new AmazonClientException("Failed to resolve AWS credentials.");
        var wrapper = new AwsKmsKeyWrapper(kms.Client, KeyArn);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Equal($"AWS KMS generate-and-wrap failed for key '{KeyArn}': Failed to resolve AWS credentials.", exception.Message);
    }

    [Fact]
    public async Task Cancellation_IsNotWrapped()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes], cts.Token));
    }

    [Fact]
    public async Task ReadKeyFileAsync_ReadsWithOrdinaryFileIo()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn);
        var path = Path.GetTempFileName();
        try
        {
            var wrapped = RandomNumberGenerator.GetBytes(184);
            await File.WriteAllBytesAsync(path, wrapped);

            Assert.Equal(wrapped, await ((IKeyWrapper)wrapper).ReadKeyFileAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Scrub_ZeroesAnExposedBuffer_AndSkipsAReadOnlyOne()
    {
        var exposed = new byte[] { 1, 2, 3 };
        AwsKmsKeyWrapper.Scrub(new MemoryStream(exposed, 0, 3, writable: false, publiclyVisible: true));
        Assert.Equal(new byte[3], exposed);

        var hidden = new byte[100];
        Array.Fill(hidden, (byte)7);
        AwsKmsKeyWrapper.Scrub(new MemoryStream(hidden));
        Assert.Equal(new byte[100], hidden);

        var readOnly = new byte[] { 1, 2, 3 };
        AwsKmsKeyWrapper.Scrub(new MemoryStream(readOnly, writable: false));
        Assert.Equal(new byte[] { 1, 2, 3 }, readOnly);
    }

    [Fact]
    public async Task ACryptoProvider_GeneratesAndRevealsItsDekThroughKms()
    {
        var wrapper = new AwsKmsKeyWrapper(FakeKms.Create().Client, KeyArn, Context);
        await using var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(wrapper, expirySeconds: 60);

        var expected = "hello, kms"u8.ToArray();
        // Encrypt zeroes the plaintext it is given, so it gets a copy.
        var plaintext = expected.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var encryptedLength = provider.Encrypt(plaintext, encrypted);
        var decrypted = new byte[provider.GetDecryptedAllocationLength(encryptedLength)];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, encryptedLength), decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }
}
