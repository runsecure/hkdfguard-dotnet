using System.Security.Cryptography;
using Azure;
using Azure.Core;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.KeyWrapping.AzureKeyVault.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.AzureKeyVault.Test;

public sealed class AzureKeyVaultKeyWrapperTests : IDisposable
{
    private const string Context = "com.example.myapp";

    private readonly FakeKeyVault _vault = new();

    public void Dispose() => _vault.Dispose();

    private AzureKeyVaultKeyWrapper Wrapper(string? context = Context, Uri? wrappingKeyId = null, Uri? signingKeyId = null)
        => new(wrappingKeyId ?? FakeKeyVault.WrappingKeyId, signingKeyId ?? FakeKeyVault.SigningKeyId, _vault.Client, context, keyFileTrust: null);

    private static async Task<byte[]> Wrap(AzureKeyVaultKeyWrapper wrapper, byte[] dek)
    {
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(dek, wrapped);
        return wrapped[..length];
    }

    private static async Task<byte[]> Unwrap(AzureKeyVaultKeyWrapper wrapper, byte[] wrapped)
    {
        var revealed = new byte[64];
        var length = await wrapper.UnwrapAsync(wrapped, revealed);
        return revealed[..length];
    }

    [Fact]
    public void Constructor_RejectsMissingOrInvalidArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultKeyWrapper(null!, FakeKeyVault.SigningKeyId, _vault.Client, null, null));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, null!, _vault.Client, null, null));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId, (TokenCredential)null!));
        Assert.ThrowsAny<ArgumentException>(() => Wrapper(wrappingKeyId: new Uri("https://example.com/not/a/key/id/at/all")));
        Assert.Throws<ArgumentException>(() => Wrapper(context: new string('x', ushort.MaxValue + 1)));
    }

    [Theory]
    [InlineData("https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap")]
    [InlineData("https://HKDFGUARD-TEST.vault.azure.net/keys/HKDFGUARD-WRAP/0123456789abcdef0123456789abcdef")]
    public void Constructor_RefusesTheSameKeyForWrappingAndSigning(string signingKeyId)
    {
        var ex = Assert.Throws<ArgumentException>(() => Wrapper(signingKeyId: new Uri(signingKeyId)));
        Assert.Contains("separate EC P-256 key", ex.Message);
    }

    [Fact]
    public void Constructor_AllowsKeysWithTheSameNameInDifferentVaults()
        => _ = Wrapper(signingKeyId: new Uri($"https://other-vault.vault.azure.net/keys/{FakeKeyVault.WrappingKeyName}"));

    [Fact]
    public async Task WrapThenUnwrap_RoundTripsTheDek()
    {
        var wrapper = Wrapper();
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await Wrap(wrapper, dek);

        Assert.Equal(dek, await Unwrap(wrapper, wrapped));
        Assert.Equal(256 + WrappedDekEnvelope.Overhead, wrapped.Length); // RSA-2048
        Assert.Equal(dek, _vault.LastWrapped);
    }

    [Fact]
    public async Task Wrap_WrapsUnderTheCurrentVersions_AndRecordsThem()
    {
        var wrapper = Wrapper();

        var parts = WrappedDekEnvelope.Parse(await Wrap(wrapper, RandomNumberGenerator.GetBytes(32)));

        Assert.Equal(_vault.CurrentVersion(FakeKeyVault.WrappingKeyName), parts.WrappingKeyVersion);
        Assert.Equal(_vault.CurrentVersion(FakeKeyVault.SigningKeyName), parts.SigningKeyVersion);
        Assert.Equal([$"wrap {FakeKeyVault.WrappingKeyId}", $"sign {FakeKeyVault.SigningKeyId}"], _vault.Calls);
    }

    [Fact]
    public async Task Unwrap_VerifiesTheSignatureFirst_ThenUnwrapsUnderTheRecordedVersions()
    {
        var wrapper = Wrapper();
        var wrapped = await Wrap(wrapper, RandomNumberGenerator.GetBytes(32));
        var wrapVersion = _vault.CurrentVersion(FakeKeyVault.WrappingKeyName);
        var signVersion = _vault.CurrentVersion(FakeKeyVault.SigningKeyName);
        _vault.Calls.Clear();

        await Unwrap(wrapper, wrapped);

        Assert.Equal(
            [$"verify {FakeKeyVault.SigningKeyId}/{signVersion}", $"unwrap {FakeKeyVault.WrappingKeyId}/{wrapVersion}"],
            _vault.Calls);
    }

    [Fact]
    public async Task Unwrap_AfterBothKeysRotate_StillRevealsOlderKeyFiles()
    {
        var wrapper = Wrapper();
        var dek = RandomNumberGenerator.GetBytes(32);
        var older = await Wrap(wrapper, dek);

        _vault.AddVersion(FakeKeyVault.WrappingKeyName, RSA.Create(2048));
        _vault.AddVersion(FakeKeyVault.SigningKeyName, ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var newer = WrappedDekEnvelope.Parse(await Wrap(wrapper, dek));

        Assert.Equal(dek, await Unwrap(wrapper, older));
        Assert.Equal(_vault.CurrentVersion(FakeKeyVault.WrappingKeyName), newer.WrappingKeyVersion);
    }

    [Fact]
    public async Task GenerateAndWrap_ProducesA32ByteDekThatReveals()
    {
        var wrapper = Wrapper();
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];

        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = await Unwrap(wrapper, wrapped[..length]);

        Assert.Equal(AzureKeyVaultKeyWrapper.GeneratedKeyLength, revealed.Length);
        Assert.False(revealed.All(b => b == 0));
    }

    [Fact]
    public async Task Unwrap_ZeroesTheRevealedKeyItReceived()
    {
        var wrapper = Wrapper();
        var wrapped = await Wrap(wrapper, RandomNumberGenerator.GetBytes(32));

        await Unwrap(wrapper, wrapped);

        Assert.All(_vault.LastRevealed!, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Unwrap_AWrappedDekForgedFromThePublicKey_IsRefused_WithoutUnwrapping()
    {
        // What anyone holding the public wrapping key can make: a real RSA-OAEP ciphertext of a DEK
        // they chose, signed with an EC key of their own.
        var chosen = RandomNumberGenerator.GetBytes(32);
        var ciphertext = _vault.PublicWrappingKey().Encrypt(chosen, RSAEncryptionPadding.OaepSHA256);
        var unsigned = WrappedDekEnvelope.BuildUnsigned(_vault.CurrentVersion(FakeKeyVault.WrappingKeyName), ciphertext);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = attackerKey.SignData(WrappedDekEnvelope.SignedData(unsigned, WrappedDekEnvelope.EncodeContext(Context)),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var forged = new byte[WrappedKeyLimits.MaxBytes];
        var length = WrappedDekEnvelope.Write(unsigned, _vault.CurrentVersion(FakeKeyVault.SigningKeyName), signature, forged);

        var revealed = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrapper().UnwrapAsync(forged.AsMemory(0, length), revealed));

        Assert.Contains("signature doesn't verify", ex.Message);
        Assert.DoesNotContain(_vault.Calls, c => c.StartsWith("unwrap", StringComparison.Ordinal));
        Assert.All(revealed, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0)]   // magic
    [InlineData(4)]   // format version
    [InlineData(5)]   // wrapping key version
    [InlineData(30)]  // ciphertext
    [InlineData(278)] // ciphertext, last byte
    [InlineData(279)] // signing key version
    [InlineData(300)] // signature
    public async Task Unwrap_AWrappedDekChangedAnywhere_IsRefused(int offset)
    {
        var wrapper = Wrapper();
        var wrapped = await Wrap(wrapper, RandomNumberGenerator.GetBytes(32));
        wrapped[offset] ^= 0x01;

        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(wrapper, wrapped));
    }

    [Fact]
    public async Task Unwrap_UnderAnotherContext_IsRefused()
    {
        var wrapped = await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32));

        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(Wrapper(context: "com.example.other"), wrapped));
        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(Wrapper(context: null), wrapped));
    }

    [Fact]
    public async Task Unwrap_ByAWrapperPinnedToOtherKeys_IsRefused()
    {
        var wrapped = await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32));
        _vault.AddVersion("other-sign", ECDsa.Create(ECCurve.NamedCurves.nistP256));

        var other = Wrapper(signingKeyId: new Uri(FakeKeyVault.VaultUri, "keys/other-sign"));

        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(other, wrapped));
    }

    [Theory]
    [InlineData(FakeKeyVault.WrappingKeyName)]
    [InlineData(FakeKeyVault.SigningKeyName)]
    public async Task Unwrap_WhenTheRecordedVersionHasBeenPurged_IsRefused(string keyName)
    {
        var version = _vault.CurrentVersion(keyName);
        var wrapped = await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32));
        _vault.AddVersion(keyName, keyName == FakeKeyVault.WrappingKeyName ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256));
        _vault.Purge(keyName, version);

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(Wrapper(), wrapped));
        Assert.IsType<RequestFailedException>(ex.InnerException);
    }

    [Fact]
    public async Task Unwrap_RefusesWhatIsNotAWrappedDek_AndZeroesTheResult()
    {
        var revealed = Enumerable.Repeat((byte)0xAA, 32).ToArray();

        await Assert.ThrowsAsync<CryptographicException>(async () => await Wrapper().UnwrapAsync(RandomNumberGenerator.GetBytes(200), revealed));

        Assert.All(revealed, b => Assert.Equal(0, b));
        Assert.Empty(_vault.Calls);
    }

    [Fact]
    public async Task Unwrap_IntoAResultTooSmall_IsRefused_AndZeroesIt()
    {
        var wrapper = Wrapper();
        var wrapped = await Wrap(wrapper, RandomNumberGenerator.GetBytes(32));
        var small = Enumerable.Repeat((byte)0xAA, 16).ToArray();

        await Assert.ThrowsAsync<ArgumentException>(async () => await wrapper.UnwrapAsync(wrapped, small));

        Assert.All(small, b => Assert.Equal(0, b));
        Assert.All(_vault.LastRevealed!, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(AzureKeyVaultKeyWrapper.MaxPlaintextLength + 1)]
    public async Task Wrap_RefusesAPlaintextRsaOaepCanNotWrap(int length)
    {
        await Assert.ThrowsAsync<ArgumentException>(async () => await Wrapper().WrapAsync(new byte[length], new byte[WrappedKeyLimits.MaxBytes]));
        Assert.Empty(_vault.Calls);
    }

    [Fact]
    public async Task Wrap_IntoAResultTooSmall_IsRefused()
    {
        await Assert.ThrowsAsync<ArgumentException>(async () => await Wrapper().WrapAsync(new byte[32], new byte[100]));
    }

    [Fact]
    public async Task Wrap_UnderAnRsaKeyTooLargeForAKeyFile_IsRefused_BeforeSigning()
    {
        _vault.AddVersion(FakeKeyVault.WrappingKeyName, RSA.Create(4096));

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));

        Assert.Contains("2048- or 3072-bit", ex.Message);
        Assert.DoesNotContain(_vault.Calls, c => c.StartsWith("sign", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Wrap_UnderAnRsa3072Key_FitsAKeyFile()
    {
        _vault.AddVersion(FakeKeyVault.WrappingKeyName, RSA.Create(3072));
        var wrapper = Wrapper();
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await Wrap(wrapper, dek);

        Assert.True(wrapped.Length <= WrappedKeyLimits.MaxBytes);
        Assert.Equal(dek, await Unwrap(wrapper, wrapped));
    }

    [Fact]
    public async Task Wrap_WhenTheSigningKeyIsNotP256_IsRefused()
    {
        _vault.SignatureOverride = s => [.. s, .. new byte[8]];

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));
        Assert.Contains("EC P-256", ex.Message);
    }

    [Theory]
    [InlineData("https://hkdfguard-test.vault.azure.net/keys/someone-else/0123456789abcdef0123456789abcdef", "instead")]
    [InlineData("https://other-vault.vault.azure.net/keys/hkdfguard-wrap/0123456789abcdef0123456789abcdef", "instead")]
    [InlineData("https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap", "instead")]
    [InlineData("not a uri", "isn't a key identifier")]
    [InlineData("https://example.com/", "isn't a key identifier")]
    public async Task Wrap_WhenKeyVaultReportsAnotherKey_IsRefused(string reported, string expected)
    {
        _vault.ReportedKeyId = _ => reported;

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public async Task Wrap_WhenKeyVaultReportsNoKey_IsRefused()
    {
        _vault.ReportedKeyId = _ => null!;

        await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));
    }

    [Theory]
    [InlineData("wrap")]
    [InlineData("sign")]
    [InlineData("verify")]
    [InlineData("unwrap")]
    public async Task KeyVaultRefusals_AreCryptographicExceptions_NamingTheErrorAndStatus(string operation)
    {
        var wrapper = Wrapper();
        var wrapped = await Wrap(wrapper, RandomNumberGenerator.GetBytes(32));
        _vault.Failures[operation] = new RequestFailedException(403, "Caller is not authorized.", "Forbidden", null);

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            if (operation is "wrap" or "sign")
                await Wrap(wrapper, new byte[32]);
            else
                await Unwrap(wrapper, wrapped);
        });

        Assert.Contains($"{operation} failed", ex.Message);
        Assert.Contains("Forbidden (HTTP 403)", ex.Message);
        Assert.IsType<RequestFailedException>(ex.InnerException);
    }

    [Fact]
    public async Task RefusalWithoutAnErrorCode_IsStillNamed()
    {
        _vault.Failures["wrap"] = new RequestFailedException(500, "Server error.");

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));
        Assert.Contains("HTTP 500", ex.Message);
    }

    [Fact]
    public async Task ClientSideFailures_AreCryptographicExceptions()
    {
        _vault.Failures["wrap"] = new InvalidOperationException("no token");

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(Wrapper(), new byte[32]));
        Assert.Contains("no token", ex.Message);
    }

    [Fact]
    public async Task Cancellation_IsLeftAsItIs()
    {
        _vault.Failures["wrap"] = new OperationCanceledException();

        await Assert.ThrowsAsync<OperationCanceledException>(async () => await Wrap(Wrapper(), new byte[32]));
    }

    [Fact]
    public void PublicConstructor_MakesNoCallUntilTheWrapperIsUsed()
        => _ = new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId, new FailingCredential());

    [Fact]
    public void ClientFactory_MakesAClientForExactlyTheKeyItIsGiven()
    {
        // Calling Key Vault would reach the network (its challenge authentication asks the vault
        // before the credential), so only the clients themselves are checked here.
        var versioned = new Uri(FakeKeyVault.WrappingKeyId + "/0123456789abcdef0123456789abcdef");

        Assert.Equal(versioned.AbsoluteUri, AzureKeyVaultKeyWrapper.ClientFactory(new FailingCredential(), null)(versioned).KeyId);
        Assert.Equal(versioned.AbsoluteUri, AzureKeyVaultKeyWrapper.ClientFactory(new FailingCredential(), new())(versioned).KeyId);
    }

    [Fact]
    public async Task ReadKeyFile_ByDefault_RefusesAFileTheCurrentUserCouldHaveReplaced()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("hkdfguard-keys-").FullName, "v1.key");
        await File.WriteAllBytesAsync(path, await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32)));
        try
        {
            if (!OperatingSystem.IsWindows() && Path.GetTempPath().StartsWith("/var/folders/", StringComparison.Ordinal))
                return; // macOS's per-user temp folder is private to its user; HkdfGuard.SecureFile.Test covers macOS

            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await Wrapper().ReadKeyFileAsync(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public async Task ACryptoProvider_GeneratesAndRevealsItsDekThroughKeyVault()
    {
        await using var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(Wrapper(), expirySeconds: 60);

        var expected = "hello, key vault"u8.ToArray();
        // Encrypt zeroes the plaintext it is given, so it gets a copy.
        var plaintext = expected.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var encryptedLength = provider.Encrypt(plaintext, encrypted);
        var decrypted = new byte[provider.GetDecryptedAllocationLength(encryptedLength)];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, encryptedLength), decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    /// <summary>A credential that never yields a token.</summary>
    private sealed class FailingCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new InvalidOperationException("No token in tests.");

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new InvalidOperationException("No token in tests.");
    }
}
