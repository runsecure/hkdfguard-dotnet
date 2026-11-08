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

    // A wrapper whose factory counts the clients it makes.
    private (AzureKeyVaultKeyWrapper Wrapper, Func<int> Created) CountingWrapper()
    {
        var created = 0;
        var wrapper = new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId,
            keyId => { Interlocked.Increment(ref created); return _vault.Client(keyId); }, Context, keyFileTrust: null);
        return (wrapper, () => Volatile.Read(ref created));
    }

    // A real wrapped DEK with its signing key version replaced by one the vault has never had.
    private static byte[] WithSigningVersion(byte[] wrapped, string version)
    {
        var parts = WrappedDekEnvelope.Parse(wrapped);
        var rewritten = new byte[WrappedKeyLimits.MaxBytes];
        var length = WrappedDekEnvelope.Write(wrapped[..parts.UnsignedLength], version, parts.Signature, rewritten);
        return rewritten[..length];
    }

    [Fact]
    public async Task Unwrap_UnderSigningVersionsKeyVaultDoesNotHave_CachesNoClient()
    {
        var wrapped = await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32));
        var (wrapper, created) = CountingWrapper();

        for (var i = 0; i < 10; i++)
        {
            var forged = WithSigningVersion(wrapped, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)));
            var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(wrapper, forged));
            Assert.IsType<RequestFailedException>(ex.InnerException);
        }

        Assert.Equal(10, created());
        Assert.Equal(0, wrapper.CachedClientCount);
        Assert.DoesNotContain(_vault.Calls, c => c.StartsWith("unwrap", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unwrap_WhoseSignatureDoesNotVerify_CachesNoClient()
    {
        var wrapped = await Wrap(Wrapper(), RandomNumberGenerator.GetBytes(32));
        wrapped[^1] ^= 0x01; // the signature's last byte
        var (wrapper, created) = CountingWrapper();

        for (var i = 0; i < 3; i++)
        {
            var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(wrapper, wrapped));
            Assert.Contains("signature doesn't verify", ex.Message);
        }

        Assert.Equal(3, created());
        Assert.Equal(0, wrapper.CachedClientCount);
    }

    [Fact]
    public async Task Unwrap_ThatSucceeds_CachesTheClientsItUsed()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var wrapped = await Wrap(Wrapper(), dek);
        var (wrapper, created) = CountingWrapper();

        Assert.Equal(dek, await Unwrap(wrapper, wrapped));
        Assert.Equal(2, created());
        Assert.Equal(2, wrapper.CachedClientCount);

        Assert.Equal(dek, await Unwrap(wrapper, wrapped));
        Assert.Equal(2, created());
    }

    [Fact]
    public async Task Wrap_ThatSucceeds_CachesTheConfiguredKeysClients_AndOneThatFails_DoesNot()
    {
        var (wrapper, created) = CountingWrapper();

        _vault.Failures["sign"] = new RequestFailedException(403, "Forbidden.", "Forbidden", null);
        await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(wrapper, new byte[32]));
        Assert.Equal(1, wrapper.CachedClientCount); // the wrapping key's; signing failed

        _vault.Failures.Clear();
        await Wrap(wrapper, new byte[32]);
        await Wrap(wrapper, new byte[32]);

        Assert.Equal(3, created());
        Assert.Equal(2, wrapper.CachedClientCount);
    }

    [Fact]
    public async Task Wrap_WhenKeyVaultReportsAnotherKey_CachesNoClient()
    {
        var (wrapper, _) = CountingWrapper();
        _vault.ReportedKeyId = id => id.Replace(FakeKeyVault.WrappingKeyName, "other-key", StringComparison.Ordinal);

        await Assert.ThrowsAsync<CryptographicException>(async () => await Wrap(wrapper, new byte[32]));

        Assert.Equal(0, wrapper.CachedClientCount);
    }

    [Fact]
    public async Task Unwrap_OfMoreThanTheWrappedKeyLimit_IsRefused_BeforeParsingOrCallingKeyVault()
    {
        var oversized = new byte[WrappedKeyLimits.MaxBytes + 1];
        var result = RandomNumberGenerator.GetBytes(64);

        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Wrapper().UnwrapAsync(oversized, result));

        Assert.Contains($"at most {WrappedKeyLimits.MaxBytes}", ex.Message);
        Assert.Empty(_vault.Calls);
        Assert.All(result, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task AVersionedSigningKeyId_AcceptsOnlyFilesSignedUnderThatVersion_WithoutAskingKeyVaultOtherwise()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var oldVersion = _vault.CurrentVersion(FakeKeyVault.SigningKeyName);
        var oldFile = await Wrap(Wrapper(), dek);

        // Rotate the signing key, and make a file under the new version.
        var newVersion = _vault.AddVersion(FakeKeyVault.SigningKeyName, ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var newFile = await Wrap(Wrapper(), dek);

        var pinnedOld = Wrapper(signingKeyId: new Uri(FakeKeyVault.SigningKeyId + "/" + oldVersion));
        var pinnedNew = Wrapper(signingKeyId: new Uri(FakeKeyVault.SigningKeyId + "/" + newVersion.ToUpperInvariant()));

        Assert.Equal(dek, await Unwrap(pinnedOld, oldFile));
        Assert.Equal(dek, await Unwrap(pinnedNew, newFile)); // versions match ignoring case

        _vault.Calls.Clear();
        var refused = await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(pinnedNew, oldFile));
        Assert.Contains($"version {oldVersion}", refused.Message);
        Assert.Contains("pinned", refused.Message);
        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(pinnedOld, newFile));
        Assert.Empty(_vault.Calls);

        // Unversioned, both are accepted: rotation needs no change.
        Assert.Equal(dek, await Unwrap(Wrapper(), oldFile));
        Assert.Equal(dek, await Unwrap(Wrapper(), newFile));
    }

    [Fact]
    public async Task AVersionedWrappingKeyId_AcceptsOnlyFilesWrappedUnderThatVersion()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var oldVersion = _vault.CurrentVersion(FakeKeyVault.WrappingKeyName);
        var oldFile = await Wrap(Wrapper(), dek);
        _vault.AddVersion(FakeKeyVault.WrappingKeyName, RSA.Create(2048));
        var newFile = await Wrap(Wrapper(), dek);

        var pinnedOld = Wrapper(wrappingKeyId: new Uri(FakeKeyVault.WrappingKeyId + "/" + oldVersion));

        Assert.Equal(dek, await Unwrap(pinnedOld, oldFile));
        _vault.Calls.Clear();
        await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(pinnedOld, newFile));
        Assert.Empty(_vault.Calls);
    }

    private sealed class ManualClock : TimeProvider
    {
        public long Ticks { get; set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Ticks;

        public void Advance(TimeSpan by) => Ticks += by.Ticks;
    }

    [Fact]
    public async Task APurgedSigningVersion_KeepsVerifyingOnlyUntilTheClientLifetimeRunsOut()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var wrapped = await Wrap(Wrapper(), dek);
        var signingVersion = WrappedDekEnvelope.Parse(wrapped).SigningKeyVersion;
        var clock = new ManualClock();
        var wrapper = new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId, _vault.Client, Context,
            keyFileTrust: null, clientLifetime: TimeSpan.FromMinutes(5), timeProvider: clock);
        Assert.Equal(dek, await Unwrap(wrapper, wrapped));

        // Revoke the signing version, as an operator would after the signing identity leaked. The
        // kept client verifies locally with the public key it already holds, so it still accepts.
        _vault.AddVersion(FakeKeyVault.SigningKeyName, ECDsa.Create(ECCurve.NamedCurves.nistP256));
        _vault.Purge(FakeKeyVault.SigningKeyName, signingVersion);
        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(dek, await Unwrap(wrapper, wrapped));

        // Past the lifetime a fresh client asks Key Vault, which no longer has the version.
        clock.Advance(TimeSpan.FromMinutes(1));
        var ex = await Assert.ThrowsAsync<CryptographicException>(async () => await Unwrap(wrapper, wrapped));
        Assert.IsType<RequestFailedException>(ex.InnerException);
    }

    [Fact]
    public async Task AnExpiredClient_IsReplaced_AndTheReplacementIsKept()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var wrapped = await Wrap(Wrapper(), dek);
        var clock = new ManualClock();
        var created = 0;
        var wrapper = new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId,
            keyId => { Interlocked.Increment(ref created); return _vault.Client(keyId); }, Context,
            keyFileTrust: null, clientLifetime: TimeSpan.FromMinutes(5), timeProvider: clock);

        await Unwrap(wrapper, wrapped);
        await Unwrap(wrapper, wrapped);
        Assert.Equal(2, created);

        clock.Advance(TimeSpan.FromMinutes(5));
        await Unwrap(wrapper, wrapped);
        await Unwrap(wrapper, wrapped);
        Assert.Equal(4, created);
        Assert.Equal(2, wrapper.CachedClientCount);
    }

    [Fact]
    public void ClientLifetime_DefaultsToFiveMinutes_AndMustBePositiveAndAtMostAnHour()
    {
        Assert.Equal(TimeSpan.FromMinutes(5), Wrapper().ClientLifetime);
        Assert.Equal(TimeSpan.FromHours(1), new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId,
            _vault.Client, Context, null, AzureKeyVaultKeyWrapper.MaxClientLifetime).ClientLifetime);

        foreach (var bad in new[] { TimeSpan.Zero, TimeSpan.FromSeconds(-1), AzureKeyVaultKeyWrapper.MaxClientLifetime + TimeSpan.FromTicks(1) })
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                new AzureKeyVaultKeyWrapper(FakeKeyVault.WrappingKeyId, FakeKeyVault.SigningKeyId, _vault.Client, Context, null, bad));
    }

    [Fact]
    public async Task ConcurrentUnwraps_UnderNewVersions_KeepOneClientPerVersion()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var wrapped = await Wrap(Wrapper(), dek);
        var (wrapper, _) = CountingWrapper();

        var revealed = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => Unwrap(wrapper, wrapped))));

        Assert.All(revealed, r => Assert.Equal(dek, r));
        Assert.Equal(2, wrapper.CachedClientCount);
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
