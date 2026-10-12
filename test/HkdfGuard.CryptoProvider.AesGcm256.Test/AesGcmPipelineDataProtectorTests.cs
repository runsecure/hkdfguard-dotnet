using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

public class AesGcmPipelineDataProtectorTests
{
    private const string Id = "Pipeline:Secret";
    private const int Version = 3;

    private static AesGcmPipelineDataProtector Create(int version = Version)
        => new(new DefaultFormatProvider(), version);

    private static string Decrypt(IPipelineDataProtector protector, string formatted, string secretIdentifier)
    {
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted)];
        var written = protector.Decrypt(formatted, secretIdentifier, result);
        return new string(result[..written]);
    }

    private static string Decrypt(IDataProtector protector, string formatted)
    {
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted)];
        var written = protector.Decrypt(formatted, result);
        return new string(result[..written]);
    }

    [Fact]
    public void ImplementsIPipelineDataProtector()
    {
        using var protector = Create();

        Assert.IsAssignableFrom<IPipelineDataProtector>(protector);
    }

    [Theory]
    [InlineData("hello")]
    [InlineData("héllo wörld ✓ 🔐")]
    [InlineData("")]
    public void EncryptDecrypt_RoundTrips(string plaintext)
    {
        using var protector = Create();

        var formatted = protector.Encrypt(plaintext, Id);

        Assert.Equal(plaintext, Decrypt(protector, formatted, Id));
    }

    [Fact]
    public void EncryptAndDecrypt_WithAnEmptySecretIdentifier_Throw()
    {
        using var protector = Create();
        var formatted = protector.Encrypt("hello", Id);

        Assert.Throws<ArgumentException>(() => protector.Encrypt("hello", ReadOnlySpan<char>.Empty));
        Assert.Throws<ArgumentException>(() => protector.Decrypt(formatted, "", new char[16]));
    }

    [Fact]
    public void EncryptAndDecrypt_WithASecretIdentifierThatIsNotValidUtf16_Throw()
    {
        // The reading side, ProtectedConfigurationRoot, refuses such a key too, so nothing written
        // here could ever be read back.
        using var protector = Create();
        var formatted = protector.Encrypt("hello", Id);

        Assert.ThrowsAny<ArgumentException>(() => protector.Encrypt("hello", "Key\uD800"));
        Assert.ThrowsAny<ArgumentException>(() => protector.Decrypt(formatted, "Key\uD800", new char[16]));
    }

    [Theory]
    [InlineData("pipeline:secret")]
    [InlineData("PIPELINE:SECRET")]
    public void SecretIdentifiers_AreCaseInsensitive_LikeConfigurationKeys(string lookup)
    {
        using var protector = Create();

        var formatted = protector.Encrypt("hello", Id);

        Assert.Equal("hello", Decrypt(protector, formatted, lookup));
    }

    [Fact]
    public void ALongSecretIdentifier_RoundTrips()
    {
        using var protector = Create();
        var longId = string.Join(':', Enumerable.Range(0, 60).Select(i => $"Section{i}"));

        var formatted = protector.Encrypt("hello", longId);

        Assert.Equal("hello", Decrypt(protector, formatted, longId));
        Assert.ThrowsAny<CryptographicException>(() => protector.Decrypt(formatted, longId + "X", new char[16]));
    }

    [Fact]
    public void KeyVersion_IsStampedOnEveryValue()
    {
        using var protector = Create(version: 42);

        var formatted = protector.Encrypt("hello", Id);

        Assert.Equal(42, protector.KeyVersion);
        Assert.StartsWith("enc::v42::", formatted);
        Assert.DoesNotContain("hello", formatted);
    }

    [Fact]
    public void Encrypt_SameValueTwice_ProducesDifferentOutput()
    {
        using var protector = Create();

        Assert.NotEqual(protector.Encrypt("hello", Id), protector.Encrypt("hello", Id));
    }

    [Fact]
    public void GetMaxDecryptedLength_IsAnUpperBoundOnTheDecryptedLength()
    {
        using var protector = Create();
        var formatted = protector.Encrypt("hello", Id);

        Assert.True(protector.GetMaxDecryptedLength(formatted) >= "hello".Length);
    }

    [Fact]
    public void OneKey_ProtectsManySecrets_EachBoundToItsOwnIdentifier()
    {
        using var protector = Create();
        const string admin = "ConnectionStrings:Admin";
        const string reporting = "ConnectionStrings:Reporting";

        var adminValue = protector.Encrypt("admin-secret", admin);
        var reportingValue = protector.Encrypt("reporting-secret", reporting);

        Assert.Equal("admin-secret", Decrypt(protector, adminValue, admin));
        Assert.Equal("reporting-secret", Decrypt(protector, reportingValue, reporting));
    }

    [Fact]
    public void Decrypt_AValueMovedToAnotherIdentifier_FailsAuthentication()
    {
        using var protector = Create();
        const string admin = "ConnectionStrings:Admin";
        const string reporting = "ConnectionStrings:Reporting";
        var adminValue = protector.Encrypt("admin-secret", admin);

        // The substitution finding 3 is about: an admin value presented under the reporting key.
        Assert.Throws<AuthenticationTagMismatchException>(() => protector.Decrypt(adminValue, reporting, new char[32]));
    }

    [Fact]
    public void Decrypt_OfAValueStampedWithAnotherVersion_ThrowsKeyNotFound()
    {
        using var protector = Create();
        var formatted = protector.Encrypt("hello", Id).Replace($"::v{Version}::", "::v99::");

        Assert.Throws<KeyNotFoundException>(() => protector.Decrypt(formatted, Id, new char[16]));
    }

    [Fact]
    public void Decrypt_UnderADifferentInstance_Fails()
    {
        using var writer = Create();
        using var reader = Create();

        var formatted = writer.Encrypt("hello", Id);

        Assert.ThrowsAny<CryptographicException>(() => reader.Decrypt(formatted, Id, new char[16]));
    }

    [Fact]
    public void Decrypt_WithMalformedInput_ThrowsFormatException()
    {
        using var protector = Create();

        Assert.Throws<FormatException>(() => protector.Decrypt("not-a-valid-format", Id, new char[16]));
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging;
        HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging = true;
        try
        {
            using var protector = Create();

            Assert.Equal("hello", Decrypt(protector, protector.Encrypt("hello", Id), Id));
        }
        finally
        {
            HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task PipelineValues_DecryptThroughAKeyRingProtectorForTheIdentifiersPurpose()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version, (byte[])key.Clone());
        var formatted = pipeline.Encrypt("hello", Id);

        using var ring = await RingHoldingAsync(key, Version);

        Assert.Equal("hello", Decrypt(ring.CreateProtector(ProtectedConfigurationPurpose.For(Id)), formatted));
    }

    [Fact]
    public async Task KeyRingValues_ForTheIdentifiersPurpose_DecryptThroughThePipelineProtector()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var ring = await RingHoldingAsync((byte[])key.Clone(), Version);
        var formatted = ring.CreateProtector(ProtectedConfigurationPurpose.For(Id)).Encrypt("hello");

        using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version, key);

        Assert.Equal("hello", Decrypt(pipeline, formatted, Id));
    }

    [Fact]
    public async Task PipelineValues_DoNotDecryptUnderAPlainPurposeOfTheSameName()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version, (byte[])key.Clone());
        var formatted = pipeline.Encrypt("hello", Id);

        using var ring = await RingHoldingAsync(key, Version);

        Assert.Throws<AuthenticationTagMismatchException>(() => ring.CreateProtector(Id).Decrypt(formatted, new char[16]));
    }

    [Fact]
    public void GetKeyAsBase64_EncodesTheKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version, (byte[])key.Clone());

        Assert.Equal(Convert.ToBase64String(key), new string(protector.GetKeyAsBase64()));
    }

    [Fact]
    public void GetKeyAsBase64_ReusesOneBuffer()
    {
        using var protector = Create();

        var first = protector.GetKeyAsBase64();
        var second = protector.GetKeyAsBase64();

        Assert.True(first.Overlaps(second, out var offset));
        Assert.Equal(0, offset);
    }

    [Fact]
    public async Task GetKeyAsBase64_IsTheKeyThatDecryptsThroughAKeyRing()
    {
        using var pipeline = Create();
        var formatted = pipeline.Encrypt("hello", Id);
        var key = Convert.FromBase64String(new string(pipeline.GetKeyAsBase64()));

        using var ring = await RingHoldingAsync(key, Version);

        Assert.Equal("hello", Decrypt(ring.CreateProtector(ProtectedConfigurationPurpose.For(Id)), formatted));
    }

    [Fact]
    public void Encrypt_CountsAgainstTheKeysBudgetAndStopsAtTheLimit()
    {
        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version,
            RandomNumberGenerator.GetBytes(32), new EncryptionBudget(warningThreshold: 1, limit: 2));

        var formatted = protector.Encrypt("one", Id);
        protector.Encrypt("two", Id);

        Assert.Equal(2, protector.EncryptionCount);
        Assert.Throws<CryptographicException>(() => protector.Encrypt("three", Id));
        Assert.Equal("one", Decrypt(protector, formatted, Id));
    }

    [Fact]
    public void Dispose_ZeroesTheKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), Version, key);

        protector.Dispose();

        Assert.All(key, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Dispose_ZeroesTheBase64Buffer()
    {
        var protector = Create();
        var base64 = protector.GetKeyAsBase64();

        protector.Dispose();

        foreach (var c in base64)
            Assert.Equal('\0', c);
    }

    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        var protector = Create();

        protector.Dispose();
        protector.Dispose();
    }

    [Fact]
    public void AfterDispose_EveryOperationThrowsObjectDisposedException()
    {
        var protector = Create();
        var formatted = protector.Encrypt("hello", Id);
        protector.Dispose();

        Assert.Throws<ObjectDisposedException>(() => protector.Encrypt("hello", Id));
        Assert.Throws<ObjectDisposedException>(() => protector.Decrypt(formatted, Id, new char[16]));
        Assert.Throws<ObjectDisposedException>(() => protector.GetKeyAsBase64().Length);
    }

    [Fact]
    public void Constructor_WithNullFormatProvider_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AesGcmPipelineDataProtector(null!, Version));
    }

    // A KeyRing whose only key, at `version`, reveals `key` - what the ring looks like once the
    // pipeline's key has been wrapped and registered.
    private static async Task<KeyRing> RingHoldingAsync(byte[] key, int version)
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var provider = await AesGcmCryptoProvider.CreateAsync(new FixedKeyWrapper(key), [1], 60);
        ring.Add(version, new HkdfGuard.DataEncryptionKey.DataEncryptionKey(provider));
        return ring;
    }

    private sealed class FixedKeyWrapper(byte[] key) : IKeyWrapper
    {
        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
        {
            key.CopyTo(result);
            return ValueTask.FromResult(key.Length);
        }

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
