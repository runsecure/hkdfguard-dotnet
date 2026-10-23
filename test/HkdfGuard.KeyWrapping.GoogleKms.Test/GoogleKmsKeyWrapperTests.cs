using System.Security.Cryptography;
using System.Text;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Grpc.Core;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.KeyWrapping.GoogleKms.Test.TestHelpers;
using HkdfGuard.SecureFile;

namespace HkdfGuard.KeyWrapping.GoogleKms.Test;

public class GoogleKmsKeyWrapperTests
{
    private const string KeyName = "projects/hkdfguard-test/locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap";
    private const string OtherKeyName = "projects/hkdfguard-test/locations/us-east1/keyRings/hkdfguard/cryptoKeys/other";
    private const string Context = "hkdfguard.test";

    private static readonly byte[] Label = "HkdfGuard-GoogleKms-wrap-v1\0"u8.ToArray();

    [Fact]
    public void Constructor_RejectsMissingAndMalformedArguments()
    {
        var kms = new FakeCloudKms();

        Assert.Throws<ArgumentNullException>(() => new GoogleKmsKeyWrapper(null!, KeyName));
        Assert.Throws<ArgumentNullException>(() => new GoogleKmsKeyWrapper(kms, null!));
        Assert.Throws<ArgumentException>("keyName", () => new GoogleKmsKeyWrapper(kms, ""));
        Assert.Throws<ArgumentException>("keyName", () => new GoogleKmsKeyWrapper(kms, "projects/p/locations/l/keyRings/r"));
        Assert.Throws<ArgumentException>("keyName", () => new GoogleKmsKeyWrapper(kms, $"{KeyName}/cryptoKeyVersions/1"));
        Assert.Throws<ArgumentException>("context", () =>
            new GoogleKmsKeyWrapper(kms, KeyName, new string('x', GoogleKmsKeyWrapper.MaxContextLength + 1)));
    }

    [Fact]
    public async Task TheLongestContext_FitsCloudKmsAadLimit()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName, new string('x', GoogleKmsKeyWrapper.MaxContextLength));

        await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]);

        Assert.True(kms.EncryptRequests[0].AdditionalAuthenticatedData.Length <= 64 * 1024);
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTripsTheDek()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var wrappedLength = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];
        var revealedLength = await wrapper.UnwrapAsync(wrapped.AsMemory(0, wrappedLength), revealed);

        Assert.Equal(32, revealedLength);
        Assert.Equal(dek, revealed);
    }

    [Fact]
    public async Task WrapAsync_SendsTheKeyLabelledContextAndChecksums_AndZeroesItsCopyOfThePlaintext()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName, Context);
        var dek = RandomNumberGenerator.GetBytes(32);

        await wrapper.WrapAsync(dek, new byte[WrappedKeyLimits.MaxBytes]);

        var request = Assert.Single(kms.EncryptRequests);
        Assert.Equal(KeyName, request.Name);
        Assert.Equal([.. Label, .. Encoding.UTF8.GetBytes(Context)], request.AdditionalAuthenticatedData.ToByteArray());
        Assert.Equal(GoogleKmsKeyWrapper.Crc32C(dek), request.PlaintextCrc32C);
        Assert.Equal(GoogleKmsKeyWrapper.Crc32C(request.AdditionalAuthenticatedData.Span), request.AdditionalAuthenticatedDataCrc32C);
        Assert.Equal(dek, kms.EncryptPlaintexts[0]);
        Assert.All(request.Plaintext.ToByteArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_PinsTheKeyAndSendsChecksums_AndZeroesTheRevealedBytes()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName, Context);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]);

        var request = Assert.Single(kms.DecryptRequests);
        Assert.Equal(KeyName, request.Name);
        Assert.Equal(wrapped[..length], request.Ciphertext.ToByteArray());
        Assert.Equal(GoogleKmsKeyWrapper.Crc32C(wrapped.AsSpan(0, length)), request.CiphertextCrc32C);
        Assert.Equal(kms.EncryptRequests[0].AdditionalAuthenticatedData, request.AdditionalAuthenticatedData);
        Assert.Equal(kms.EncryptRequests[0].AdditionalAuthenticatedDataCrc32C, request.AdditionalAuthenticatedDataCrc32C);
        Assert.All(kms.DecryptPlaintexts[0].ToByteArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task ANullAndAnEmptyContext_BindTheLabelOnly()
    {
        var kms = new FakeCloudKms();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(wrapped);

        await new GoogleKmsKeyWrapper(kms, KeyName, "").UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]);

        Assert.Equal(Label, kms.EncryptRequests[0].AdditionalAuthenticatedData.ToByteArray());
    }

    [Fact]
    public async Task GenerateAndWrapAsync_WrapsAFresh32ByteDek_AndZeroesIt()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName, Context);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];
        var revealedLength = await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed);

        Assert.Equal(GoogleKmsKeyWrapper.GeneratedKeyLength, revealedLength);
        Assert.Equal(revealed, kms.EncryptPlaintexts[0]);
        Assert.False(revealed.All(b => b == 0));
        Assert.All(kms.EncryptRequests[0].Plaintext.ToByteArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task KeyFilesFromEveryVersion_StillUnwrapAfterTheKeyIsRotated()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName, Context);
        var before = new byte[WrappedKeyLimits.MaxBytes];
        var beforeLength = await wrapper.GenerateAndWrapAsync(before);

        kms.Rotate(KeyName);
        var after = new byte[WrappedKeyLimits.MaxBytes];
        var afterLength = await wrapper.GenerateAndWrapAsync(after);

        Assert.Equal(32, await wrapper.UnwrapAsync(before.AsMemory(0, beforeLength), new byte[32]));
        Assert.Equal(32, await wrapper.UnwrapAsync(after.AsMemory(0, afterLength), new byte[32]));
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherKey_FailsAndZeroesTheResult()
    {
        var kms = new FakeCloudKms();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new GoogleKmsKeyWrapper(kms, OtherKeyName, Context).WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        var result = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName, Context).UnwrapAsync(wrapped.AsMemory(0, length), result));

        Assert.IsType<RpcException>(exception.InnerException);
        Assert.Equal($"Cloud KMS unwrap failed for key '{KeyName}': InvalidArgument: Decryption failed: the ciphertext is invalid.", exception.Message);
        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_UnderAnotherContext_Fails()
    {
        var kms = new FakeCloudKms();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new GoogleKmsKeyWrapper(kms, KeyName, Context).GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName, "other").UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [Fact]
    public async Task UnwrapAsync_ACiphertextMadeWithoutTheLabel_IsRefused()
    {
        // What any other use of the same key produces: the right key, but not an HkdfGuard DEK.
        var kms = new FakeCloudKms();
        var foreign = await kms.EncryptAsync(new EncryptRequest
        {
            Name = KeyName,
            Plaintext = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(32)),
            AdditionalAuthenticatedData = ByteString.CopyFromUtf8(Context),
        });

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName, Context).UnwrapAsync(foreign.Ciphertext.ToByteArray(), new byte[32]));
    }

    [Fact]
    public async Task UnwrapAsync_WhenTampered_Fails()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        wrapped[length - 1] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(WrappedKeyLimits.MaxBytes + 1)]
    public async Task UnwrapAsync_OutOfBounds_FailsWithoutCallingKms(int size)
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[size], new byte[32]));

        Assert.Empty(kms.DecryptRequests);
    }

    [Fact]
    public async Task UnwrapAsync_WhenTheKeyDoesNotFit_FailsZeroesTheResultAndScrubsThePlaintext()
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);

        var result = Enumerable.Repeat((byte)0xAA, 16).ToArray();
        await Assert.ThrowsAsync<ArgumentException>("result", async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), result));

        Assert.All(result, b => Assert.Equal(0, b));
        Assert.All(kms.DecryptPlaintexts[0].ToByteArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task UnwrapAsync_WhenKmsReturnsNoPlaintext_Fails()
    {
        var kms = new FakeCloudKms { OnDecrypt = _ => new DecryptResponse { PlaintextCrc32C = 0 } };
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[64], new byte[32]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnwrapAsync_WhenThePlaintextDoesNotMatchItsChecksum_FailsAndScrubsIt(bool missing)
    {
        var plaintext = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(32));
        var kms = new FakeCloudKms
        {
            OnDecrypt = _ => new DecryptResponse
            {
                Plaintext = plaintext,
                PlaintextCrc32C = missing ? null : GoogleKmsKeyWrapper.Crc32C(plaintext.Span) ^ 1,
            },
        };
        var result = Enumerable.Repeat((byte)0xAA, 32).ToArray();

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).UnwrapAsync(new byte[64], result));

        Assert.Contains("corrupted in transit", exception.Message);
        Assert.All(result, b => Assert.Equal(0, b));
        Assert.All(plaintext.ToByteArray(), b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(GoogleKmsKeyWrapper.MaxPlaintextLength + 1)]
    public async Task WrapAsync_RejectsAPlaintextKmsWouldRefuse(int size)
    {
        var kms = new FakeCloudKms();
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);

        await Assert.ThrowsAsync<ArgumentException>("plaintext", async () =>
            await wrapper.WrapAsync(new byte[size], new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Empty(kms.EncryptRequests);
    }

    [Fact]
    public async Task WrapAsync_WhenResultIsTooSmall_Throws()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName);

        await Assert.ThrowsAsync<ArgumentException>("result", async () =>
            await wrapper.WrapAsync(new byte[32], new byte[8]));
    }

    [Theory]
    [InlineData(OtherKeyName + "/cryptoKeyVersions/1")]
    [InlineData(KeyName)]
    [InlineData(KeyName + "/cryptoKeyVersions/")]
    [InlineData(KeyName + "/cryptoKeyVersions/1/x")]
    [InlineData("")]
    public async Task WrapAsync_RefusesAResponseFromAnyVersionButThisKeys(string reportedName)
    {
        var kms = new FakeCloudKms();
        kms.OnEncrypt = request => Respond(request, response => response.Name = reportedName);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Equal($"Cloud KMS wrap for key '{KeyName}' reported key version '{reportedName}' instead.", exception.Message);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task WrapAsync_RefusesAResponseThatDidNotVerifyTheRequestChecksums(bool plaintextVerified, bool aadVerified)
    {
        var kms = new FakeCloudKms();
        kms.OnEncrypt = request => Respond(request, response =>
        {
            response.VerifiedPlaintextCrc32C = plaintextVerified;
            response.VerifiedAdditionalAuthenticatedDataCrc32C = aadVerified;
        });

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Contains("didn't verify the request's checksums", exception.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrapAsync_RefusesACiphertextThatDoesNotMatchItsChecksum(bool missing)
    {
        var kms = new FakeCloudKms();
        kms.OnEncrypt = request => Respond(request, response =>
            response.CiphertextCrc32C = missing ? null : response.CiphertextCrc32C ^ 1);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Contains("corrupted in transit", exception.Message);
    }

    [Fact]
    public async Task WrapAsync_WhenKmsReturnsNoCiphertext_Fails()
    {
        var kms = new FakeCloudKms();
        kms.OnEncrypt = request => Respond(request, response => response.Ciphertext = ByteString.Empty);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public async Task WrapAsync_RefusesACiphertextOverTheKeyFileLimit()
    {
        var kms = new FakeCloudKms();
        var ciphertext = new byte[WrappedKeyLimits.MaxBytes + 1];
        kms.OnEncrypt = request => Respond(request, response =>
        {
            response.Ciphertext = ByteString.CopyFrom(ciphertext);
            response.CiphertextCrc32C = GoogleKmsKeyWrapper.Crc32C(ciphertext);
        });

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[2 * WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public async Task AServiceRefusal_BecomesACryptographicExceptionNamingTheStatus()
    {
        var kms = new FakeCloudKms
        {
            OnEncrypt = _ => throw FakeCloudKms.Error(StatusCode.PermissionDenied, "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied."),
        };
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.WrapAsync(new byte[32], new byte[WrappedKeyLimits.MaxBytes]));

        Assert.Equal($"Cloud KMS wrap failed for key '{KeyName}': PermissionDenied: Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied.", exception.Message);
        Assert.IsType<RpcException>(exception.InnerException);
    }

    [Fact]
    public async Task AClientSideFailure_BecomesACryptographicException()
    {
        var kms = new FakeCloudKms { OnDecrypt = _ => throw new InvalidOperationException("The Application Default Credentials are not available.") };
        var wrapper = new GoogleKmsKeyWrapper(kms, KeyName);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[64], new byte[32]));

        Assert.Equal($"Cloud KMS unwrap failed for key '{KeyName}': The Application Default Credentials are not available.", exception.Message);
        Assert.IsType<InvalidOperationException>(exception.InnerException);
    }

    [Fact]
    public async Task ACryptographicExceptionFromTheClient_IsNotWrappedAgain()
    {
        var thrown = new CryptographicException("from the client");
        var kms = new FakeCloudKms { OnDecrypt = _ => throw thrown };

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).UnwrapAsync(new byte[64], new byte[32]));

        Assert.Same(thrown, exception);
    }

    [Fact]
    public async Task Cancellation_IsReportedAsCancellation()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes], cts.Token));

        Assert.Equal(cts.Token, exception.CancellationToken);
        Assert.IsType<RpcException>(exception.InnerException);
    }

    [Fact]
    public async Task AnOperationCanceledExceptionFromTheClient_IsLeftAsItIs()
    {
        var kms = new FakeCloudKms { OnEncrypt = _ => throw new OperationCanceledException("from the client") };

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public async Task ACancelledStatusTheCallerDidNotAskFor_IsAFailure()
    {
        var kms = new FakeCloudKms { OnEncrypt = _ => throw FakeCloudKms.Error(StatusCode.Cancelled, "Canceled by the server.") };

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new GoogleKmsKeyWrapper(kms, KeyName).GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));
    }

    [Fact]
    public void Crc32C_MatchesTheCastagnoliCheckValue()
    {
        Assert.Equal(0xE3069283L, GoogleKmsKeyWrapper.Crc32C("123456789"u8));
        Assert.Equal(0L, GoogleKmsKeyWrapper.Crc32C([]));
    }

    [Fact]
    public void Scrub_ZeroesTheBytesAByteStringHolds()
    {
        var bytes = ByteString.CopyFrom(1, 2, 3);
        GoogleKmsKeyWrapper.Scrub(bytes);
        Assert.Equal(new byte[3], bytes.ToByteArray());
    }

    [Fact]
    public async Task ACryptoProvider_GeneratesAndRevealsItsDekThroughKms()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context);
        await using var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(wrapper, expirySeconds: 60);

        var expected = "hello, cloud kms"u8.ToArray();
        // Encrypt zeroes the plaintext it is given, so it gets a copy.
        var plaintext = expected.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var encryptedLength = provider.Encrypt(plaintext, encrypted);
        var decrypted = new byte[provider.GetDecryptedAllocationLength(encryptedLength)];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, encryptedLength), decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public async Task ReadKeyFile_ByDefault_RefusesAFileTheCurrentUserCouldHaveReplaced()
    {
        // The user's temp folder (Windows) or the shared /tmp (Linux, macOS): neither is somewhere
        // only administrators can write.
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context);
        var path = Path.Combine(Directory.CreateTempSubdirectory("hkdfguard-keys-").FullName, "v1.key");
        await File.WriteAllBytesAsync(path, RandomNumberGenerator.GetBytes(89));
        try
        {
            if (!OperatingSystem.IsWindows() && Path.GetTempPath().StartsWith("/var/folders/", StringComparison.Ordinal))
                return; // macOS's per-user temp folder is private to its user; TrustedKeyFileTests covers macOS

            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await wrapper.ReadKeyFileAsync(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [WindowsFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ReadKeyFile_WithTheWritersAccountTrusted_ReadsTheFile()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context, WindowsTempDirectory.TrustCurrentUser);
        using var dir = new WindowsTempDirectory();

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var path = dir.Write("v1.key", wrapped[..length]);

        Assert.Equal(wrapped[..length], await wrapper.ReadKeyFileAsync(path));
    }

    [WindowsFact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task ReadKeyFile_TrustingEveryone_IsRefused()
    {
        var wrapper = new GoogleKmsKeyWrapper(new FakeCloudKms(), KeyName, Context,
            new KeyFileTrust { WindowsPrincipals = ["S-1-1-0"] });
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("v1.key", RandomNumberGenerator.GetBytes(89));

        await Assert.ThrowsAsync<ArgumentException>(async () => await wrapper.ReadKeyFileAsync(path));
    }

    // What the fake Cloud KMS would answer, changed by the test.
    private static EncryptResponse Respond(EncryptRequest request, Action<EncryptResponse> change)
    {
        var fake = new FakeCloudKms();
        var response = fake.EncryptAsync(request).GetAwaiter().GetResult();
        change(response);
        return response;
    }
}
