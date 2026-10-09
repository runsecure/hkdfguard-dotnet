using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Diagnostics;
using HkdfGuard.EncryptedConfiguration.Test.TestHelpers;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.EncryptedConfiguration.Test;

public class ProtectedConfigurationRootTests
{
    private static async Task<KeyRing> CreateKeyRingAsync()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));
        ring.Add(1, key);
        return ring;
    }

    private static IConfigurationRoot CreateConfigurationRoot(KeyRing keyRing, params (string Key, string PlaintextValue)[] protectedValues)
    {
        var values = new Dictionary<string, string?>();
        foreach (var (key, plaintext) in protectedValues)
            values[key] = keyRing.CreateProtector(ProtectedConfigurationPurpose.For(key)).Encrypt(plaintext);

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static ProtectedConfigurationRoot CreateSut(KeyRing keyRing, out IConfigurationRoot configurationRoot,
        params (string Key, string PlaintextValue)[] protectedValues)
    {
        configurationRoot = CreateConfigurationRoot(keyRing, protectedValues);
        return new ProtectedConfigurationRoot(configurationRoot, keyRing);
    }

    [Fact]
    public async Task Decrypt_Chars_WithKnownName_RoundTrips()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _, ("ConnectionStrings:Db", "Server=db;Password=hunter2"));

        var result = new char[64];
        var written = sut.Decrypt("ConnectionStrings:Db", result);

        Assert.True(written > 0);
        Assert.Equal("Server=db;Password=hunter2", new string(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_Bytes_WithKnownName_RoundTrips()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _, ("Secrets:ApiKey", "top-secret-api-key"));

        var result = new byte[64];
        var written = sut.Decrypt("Secrets:ApiKey", result);

        Assert.True(written > 0);
        Assert.Equal("top-secret-api-key", System.Text.Encoding.UTF8.GetString(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_Chars_HandlesMultiByteUtf8()
    {
        var keyRing = await CreateKeyRingAsync();
        const string plaintext = "héllo wörld 日本語";
        var sut = CreateSut(keyRing, out _, ("Secret", plaintext));

        var result = new char[plaintext.Length];
        var written = sut.Decrypt("Secret", result);

        Assert.True(written > 0);
        Assert.Equal(plaintext, new string(result, 0, written));
    }

    [Fact]
    public async Task Decrypt_Chars_WithUnknownName_ReturnsZero()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _);

        var written = sut.Decrypt("missing", new char[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public async Task Decrypt_Bytes_WithUnknownName_ReturnsZero()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _);

        var written = sut.Decrypt("missing", new byte[16]);

        Assert.Equal(0, written);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_WithKnownName_ReturnsTrueAndSafeUpperBound()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _, ("Secret", "some plaintext value"));

        var found = sut.TryGetMaxDecryptedLength("Secret", out var maxLength);
        Assert.True(found);

        var result = new byte[maxLength];
        var written = sut.Decrypt("Secret", result);
        Assert.True(maxLength >= written);
    }

    [Fact]
    public async Task TryGetMaxDecryptedLength_WithUnknownName_ReturnsFalse()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _);

        var found = sut.TryGetMaxDecryptedLength("missing", out var maxLength);

        Assert.False(found);
        Assert.Equal(0, maxLength);
    }

    [Fact]
    public async Task Decrypt_Chars_WithMalformedValue_ThrowsFormatException()
    {
        var keyRing = await CreateKeyRingAsync();
        var configurationRoot = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Bad"] = "not-a-protected-value" })
            .Build();
        var sut = new ProtectedConfigurationRoot(configurationRoot, keyRing);

        Assert.Throws<FormatException>(() => sut.Decrypt("Bad", new char[16]));
    }

    [Fact]
    public async Task Decrypt_Bytes_WithMalformedValue_ThrowsFormatException()
    {
        var keyRing = await CreateKeyRingAsync();
        var configurationRoot = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Bad"] = "not-a-protected-value" })
            .Build();
        var sut = new ProtectedConfigurationRoot(configurationRoot, keyRing);

        Assert.Throws<FormatException>(() => sut.Decrypt("Bad", new byte[16]));
    }

    [Fact]
    public async Task Decrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        var original = HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging;
        try
        {
            HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging = true;

            var keyRing = await CreateKeyRingAsync();
            var sut = CreateSut(keyRing, out _, ("Secret", "top secret"));

            var charResult = new char[32];
            var charsWritten = sut.Decrypt("Secret", charResult);
            Assert.True(charsWritten > 0);
            Assert.Equal("top secret", new string(charResult, 0, charsWritten));

            var byteResult = new byte[32];
            var bytesWritten = sut.Decrypt("Secret", byteResult);
            Assert.True(bytesWritten > 0);
            Assert.Equal("top secret", System.Text.Encoding.UTF8.GetString(byteResult, 0, bytesWritten));
        }
        finally
        {
            HkdfGuardTelemetry.EncryptedConfiguration.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task Indexer_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out var configurationRoot, ("PlainKey", "value"));

        // The indexer reads the raw (still-protected) string, unlike Decrypt.
        Assert.Equal(configurationRoot["PlainKey"], sut["PlainKey"]);

        sut["NewKey"] = "new-value";
        Assert.Equal("new-value", configurationRoot["NewKey"]);
    }

    [Fact]
    public async Task Providers_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out var configurationRoot);

        Assert.Same(configurationRoot.Providers, sut.Providers);
    }

    [Fact]
    public async Task GetSection_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out var configurationRoot, ("Parent:Child", "value"));

        var section = sut.GetSection("Parent");

        Assert.Equal(configurationRoot.GetSection("Parent").Path, section.Path);
        Assert.Equal(configurationRoot.GetSection("Parent")["Child"], section["Child"]);
    }

    [Fact]
    public async Task GetChildren_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out var configurationRoot, ("Parent:Child", "value"));

        var sutChildKeys = sut.GetChildren().Select(c => c.Key).ToList();
        var rootChildKeys = configurationRoot.GetChildren().Select(c => c.Key).ToList();

        Assert.Equal(rootChildKeys, sutChildKeys);
    }

    [Fact]
    public async Task GetReloadToken_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out var configurationRoot);

        Assert.NotNull(sut.GetReloadToken());
        Assert.Same(configurationRoot.GetReloadToken(), sut.GetReloadToken());
    }

    [Fact]
    public async Task Reload_DelegatesToUnderlyingConfigurationRoot()
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _);

        var exception = Record.Exception(() => sut.Reload());

        Assert.Null(exception);
    }

    private static string DecryptToString(ProtectedConfigurationRoot sut, string name)
    {
        var result = new char[64];
        var written = sut.Decrypt(name, result);
        return new string(result, 0, written);
    }

    [Fact]
    public async Task Decrypt_AValueCopiedToAnotherKey_FailsAuthenticationForBothOverloads()
    {
        var keyRing = await CreateKeyRingAsync();
        var adminValue = keyRing.CreateProtector(ProtectedConfigurationPurpose.For("ConnectionStrings:Admin")).Encrypt("admin-secret");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Admin"] = adminValue,
            ["ConnectionStrings:Reporting"] = adminValue,   // an attacker swapped the admin value in
        }).Build();
        var sut = new ProtectedConfigurationRoot(configuration, keyRing);

        Assert.Equal("admin-secret", DecryptToString(sut, "ConnectionStrings:Admin"));
        Assert.Throws<AuthenticationTagMismatchException>(() => sut.Decrypt("ConnectionStrings:Reporting", new char[64]));
        Assert.Throws<AuthenticationTagMismatchException>(() => sut.Decrypt("ConnectionStrings:Reporting", new byte[64]));
    }

    [Fact]
    public async Task Decrypt_AValueWrittenUnderTheOldSharedPurpose_NoLongerDecrypts()
    {
        var keyRing = await CreateKeyRingAsync();
        var legacy = keyRing.CreateProtector(ProtectedConfigurationPurpose.Prefix).Encrypt("secret");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Secret"] = legacy }).Build();
        var sut = new ProtectedConfigurationRoot(configuration, keyRing);

        Assert.Throws<AuthenticationTagMismatchException>(() => sut.Decrypt("Secret", new char[64]));
    }

    [Theory]
    [InlineData("connectionstrings:admin")]
    [InlineData("CONNECTIONSTRINGS:ADMIN")]
    [InlineData("ConnectionStrings:Admin")]
    public async Task Decrypt_IsCaseInsensitiveOnTheKey_LikeConfigurationItself(string lookupKey)
    {
        var keyRing = await CreateKeyRingAsync();
        var sut = CreateSut(keyRing, out _, ("ConnectionStrings:Admin", "admin-secret"));

        Assert.Equal("admin-secret", DecryptToString(sut, lookupKey));
    }

    [Fact]
    public async Task Decrypt_ReadsAValueWrittenByAPipelineDataProtectorWithTheKeysAad()
    {
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 1);
        var formatted = pipeline.Encrypt("from-the-pipeline", "Database:Password");
        var dek = Convert.FromBase64String(new string(pipeline.GetKeyAsBase64()));

        using var keyRing = new KeyRing(new DefaultFormatProvider());
        keyRing.Add(1, new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(dek), [1], 60)));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Database:Password"] = formatted }).Build();
        var sut = new ProtectedConfigurationRoot(configuration, keyRing);

        Assert.Equal("from-the-pipeline", DecryptToString(sut, "Database:Password"));
    }

    [Fact]
    public async Task Decrypt_AValueMovedBetweenKeysThatOnlyUpperCaseAlike_FailsAuthentication()
    {
        // "ſecret" (long s) and "Secret" are different configuration keys, though both upper-case
        // to "SECRET" under ToUpperInvariant - they must not share a purpose.
        var keyRing = await CreateKeyRingAsync();
        var value = keyRing.CreateProtector(ProtectedConfigurationPurpose.For("Secret")).Encrypt("real-secret");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Secret"] = value,
            ["\u017Fecret"] = value,
        }).Build();
        var sut = new ProtectedConfigurationRoot(configuration, keyRing);

        Assert.Equal("real-secret", DecryptToString(sut, "Secret"));
        Assert.Throws<AuthenticationTagMismatchException>(() => sut.Decrypt("\u017Fecret", new char[64]));
    }
}
