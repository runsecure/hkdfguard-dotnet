using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Diagnostics;
using HkdfGuard.Pipeline;
using HkdfGuard.SecureFile;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.Cache.JsonSecretsFile.Test;

/// <summary>A pipeline writer over values held in memory, so a test can read exactly what WriteJsonSecrets writes.</summary>
internal sealed class InMemoryWriter(IPipelineDataProtector protector, IReadOnlyDictionary<string, string> secrets)
    : SecretPipelineWriter(protector, secrets.Keys.ToList(), _ => true)
{
    protected override Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        ProtectSecret(Encoding.UTF8.GetBytes(secrets[name]), requests, values);
        return Task.CompletedTask;
    }
}

/// <summary>JsonSecretsFileReadOnlyCache over a real file TrustedFile accepts, with values written by a ring's protectors or a pipeline.</summary>
public sealed class JsonSecretsFileReadOnlyCacheTests : IDisposable
{
    private readonly TrustedTempDirectory _dir = new();

    private string FilePath => Path.Join(_dir.Path, "secrets.json");

    public void Dispose() => _dir.Dispose();

    private static async Task<IDataEncryptionKey> NewKeyAsync(byte[]? key = null)
        => new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(key ?? RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));

    private static async Task<KeyRing> NewRingAsync() => TestRing.For(await NewKeyAsync());

    private JsonSecretsFileReadOnlyCache CreateCache(IKeyRing ring, int maxFileLength = JsonSecretsFileReadOnlyCache.DefaultMaxFileLength)
        => new(FilePath, _dir.Trust, ring, new DefaultFormatProvider(), maxFileLength);

    private static string Encrypt(KeyRing ring, string name, string value)
        => ring.CreateProtector(ProtectedConfigurationPurpose.For(name)).Encrypt(value);

    // Writes each secret encrypted for its name, as one JSON object.
    private void Write(KeyRing ring, params (string Name, string Value)[] secrets)
        => WriteRaw(JsonSerializer.Serialize(secrets.ToDictionary(s => s.Name, s => Encrypt(ring, s.Name, s.Value))));

    private void WriteRaw(string json) => File.WriteAllText(FilePath, json);

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task WhatAPipelineWrites_DecryptsUnderTheKeyItWraps()
    {
        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 1);
        using var writer = new InMemoryWriter(protector, new Dictionary<string, string> { ["db-password"] = "pässwörd", ["api-key"] = "key" });
        await writer.PullSecretsAsync();
        writer.WriteJsonSecrets(FilePath);

        // What the application holds once the pipeline's key has been wrapped and unwrapped.
        var ring = TestRing.For(await NewKeyAsync(Convert.FromBase64String(new string(protector.GetKeyAsBase64()))));
        var cache = CreateCache(ring);

        Assert.Equal("pässwörd", DecryptString(cache, "db-password"));
        Assert.Equal("key", DecryptString(cache, "api-key"));
    }

    [Fact]
    public async Task AValue_DecryptsThroughEveryOverload_UnderItsNameIgnoringAsciiCase()
    {
        var ring = await NewRingAsync();
        Write(ring, ("Db-Password", "value"));
        var cache = CreateCache(ring);

        Assert.Equal("value", DecryptString(cache, "Db-Password"));
        Assert.Equal("value", DecryptString(cache, "DB-PASSWORD"));
        var bytes = new byte[16];
        Assert.Equal("value", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("db-password", bytes)));
        Assert.True(cache.TryGetMaxDecryptedLength("Db-Password", out var max));
        Assert.True(max >= 5);

        var chars = new char[16];
        Assert.Equal("value", new string(chars, 0, await cache.DecryptAsync("Db-Password", chars.AsMemory())));
        Assert.Equal("value", Encoding.UTF8.GetString(bytes, 0, await cache.DecryptAsync("Db-Password", bytes.AsMemory())));
        Assert.Equal(max, await cache.GetMaxDecryptedLengthAsync("Db-Password"));
    }

    [Fact]
    public async Task TheFile_IsReadOnce_EvenByConcurrentLookups_ThenServedFromMemory()
    {
        var ring = await NewRingAsync();
        var secrets = Enumerable.Range(0, 200).Select(i => ($"secret-{i:D3}", $"value-{i}")).ToArray();
        Write(ring, secrets);
        var cache = CreateCache(ring);

        var results = await Task.WhenAll(secrets.Select(s => Task.Run(async () =>
        {
            var chars = new char[64];
            return new string(chars, 0, await cache.DecryptAsync(s.Item1, chars.AsMemory()));
        })));
        File.Delete(FilePath);

        Assert.Equal(secrets.Select(s => s.Item2), results);
        Assert.Equal("value-7", DecryptString(cache, "secret-007"));
    }

    [Fact]
    public async Task ANameTheFileDoesntHold_OrThatCantBeOne_IsMissing()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var cache = CreateCache(ring);

        foreach (var name in new[] { "absent", "", ".hidden", "../item", "ıtem", "it em" })
        {
            Assert.Equal(0, cache.Decrypt(name, new byte[16]));
            Assert.Equal(0, await cache.DecryptAsync(name, new byte[16].AsMemory()));
            Assert.Equal(0, cache.Decrypt(name, new char[16]));
            Assert.False(cache.TryGetMaxDecryptedLength(name, out var max));
            Assert.Equal(0, max);
            Assert.Equal(0, await cache.GetMaxDecryptedLengthAsync(name));
        }
    }

    [Fact]
    public async Task AMissingFile_ReportsEverySecretMissing_AndIsntRemembered()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var cache = CreateCache(ring);
        File.Delete(FilePath);

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
        Assert.Equal(0, await cache.DecryptAsync("item", new char[16].AsMemory()));

        Write(ring, ("item", "later"));
        Assert.Equal("later", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task AFolderRemovedAfterConstruction_ReportsEverySecretMissing()
    {
        var ring = await NewRingAsync();
        var folder = Directory.CreateDirectory(Path.Join(_dir.Path, "sub")).FullName;
        var path = Path.Join(folder, "secrets.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, string> { ["item"] = Encrypt(ring, "item", "value") }));
        var cache = new JsonSecretsFileReadOnlyCache(path, _dir.Trust, ring, new DefaultFormatProvider());
        Directory.Delete(folder, recursive: true);

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Theory]
    [InlineData("", "valid JSON")]
    [InlineData("not json", "valid JSON")]
    [InlineData("""["item"]""", "not an object of secrets")]
    [InlineData("""{"item":1}""", "no value for 'item'")]
    [InlineData("""{"item":{"a":"b"}}""", "no value for 'item'")]
    [InlineData("""{"item":null}""", "no value for 'item'")]
    [InlineData("""{"item":"  "}""", "no value for 'item'")]
    [InlineData("""{"../item":"x"}""", "isn't a secret's name")]
    [InlineData("""{"item":"{0}","ITEM":"{0}"}""", "'ITEM' more than once")]
    [InlineData("""{"item":"{0}"} {}""", "valid JSON")]
    [InlineData("""{"item":"{0}" """, "valid JSON")]
    public async Task AFileThatIsntTheSecretsObject_IsRefused_AndNotKept(string json, string problem)
    {
        var ring = await NewRingAsync();
        WriteRaw(json.Replace("{0}", Encrypt(ring, "item", "value"), StringComparison.Ordinal));
        var cache = CreateCache(ring);

        var ex = Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
        Assert.Contains(problem, ex.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new char[16]));

        Write(ring, ("item", "fixed"));
        Assert.Equal("fixed", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task AValueMovedUnderAnotherName_FailsTheWholeFile()
    {
        var ring = await NewRingAsync();
        WriteRaw(JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["reader"] = Encrypt(ring, "reader", "fine"),
            ["writer"] = Encrypt(ring, "reader", "moved"),
        }));
        var cache = CreateCache(ring);

        Assert.ThrowsAny<CryptographicException>(() => cache.Decrypt("reader", new byte[16]));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await cache.DecryptAsync("reader", new char[16].AsMemory()));
    }

    [Fact]
    public async Task AValueUnderAKeyVersionTheRingDoesntHold_FailsTheWholeFile()
    {
        var ring = await NewRingAsync();
        WriteRaw(JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["item"] = Encrypt(ring, "item", "fine"),
            ["old"] = new DefaultFormatProvider().Format(new KeyTrackingValue { KeyVersion = 7, Value = RandomNumberGenerator.GetBytes(40) }),
        }));

        Assert.Throws<KeyNotFoundException>(() => CreateCache(ring).Decrypt("item", new byte[16]));
    }

    [Fact]
    public async Task ValuesUnderOlderKeyVersions_StillDecryptAfterRotation()
    {
        var ring = await NewRingAsync();
        var old = Encrypt(ring, "item", "old");
        ring.Add(2, await NewKeyAsync());
        WriteRaw(JsonSerializer.Serialize(new Dictionary<string, string> { ["item"] = old, ["other"] = Encrypt(ring, "other", "new") }));
        var cache = CreateCache(ring);

        Assert.Equal("old", DecryptString(cache, "item"));
        Assert.Equal("new", DecryptString(cache, "other"));
    }

    [Fact]
    public async Task AFileInAnUntrustedLocation_IsRefused_AndNotKept()
    {
        if (!OperatingSystem.IsWindows() && Environment.UserName == "root")
            return; // root's files are trusted

        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var untrusted = new JsonSecretsFileReadOnlyCache(FilePath, KeyFileTrust.AdministratorsOnly, ring, new DefaultFormatProvider());

        Assert.Throws<UnauthorizedAccessException>(() => untrusted.Decrypt("item", new byte[16]));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await untrusted.DecryptAsync("item", new byte[16].AsMemory()));
        Assert.Equal("value", DecryptString(CreateCache(ring), "item"));
    }

    [Fact]
    public async Task AFileOverTheMaximumLength_IsRefused()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var cache = CreateCache(ring, maxFileLength: 16);

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("item", new byte[16]));
        await Assert.ThrowsAsync<InvalidDataException>(async () => await cache.GetMaxDecryptedLengthAsync("item"));
    }

    [Fact]
    public async Task ALargeValue_DecryptsAsCharacters_ThroughAPinnedBuffer()
    {
        // Over the default format's limit, so ring and cache both allow longer values.
        var format = new DefaultFormatProvider(maxEncryptedLength: 16 * 1024);
        var ring = new KeyRing(format);
        ring.Add(1, await NewKeyAsync());
        var value = new string('x', ArrayUtility.MaxStackBytes + 10);
        Write(ring, ("large", value));
        var cache = new JsonSecretsFileReadOnlyCache(FilePath, _dir.Trust, ring, format);

        var result = new char[value.Length];
        Assert.Equal(value.Length, cache.Decrypt("large", result.AsSpan()));
        Assert.Equal(value, new string(result));
    }

    [Fact]
    public async Task ACancelledToken_Throws()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var cache = CreateCache(ring);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await cache.DecryptAsync("item", new byte[16].AsMemory(), new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task SensitiveLogging_DoesntChangeTheResult()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var original = HkdfGuardTelemetry.Cache.EnableSensitiveLogging;
        HkdfGuardTelemetry.Cache.EnableSensitiveLogging = true;
        try
        {
            Assert.Equal("value", DecryptString(CreateCache(ring), "item"));
        }
        finally
        {
            HkdfGuardTelemetry.Cache.EnableSensitiveLogging = original;
        }
    }

    [Fact]
    public async Task Constructor_ValidatesItsArguments()
    {
        var ring = await NewRingAsync();
        var format = new DefaultFormatProvider();
        var trust = _dir.Trust;
        Write(ring, ("item", "value"));

        Assert.Throws<ArgumentNullException>(() => new JsonSecretsFileReadOnlyCache(null!, trust, ring, format));
        Assert.Throws<ArgumentException>(() => new JsonSecretsFileReadOnlyCache("", trust, ring, format));
        Assert.Throws<ArgumentNullException>(() => new JsonSecretsFileReadOnlyCache(FilePath, null!, ring, format));
        Assert.Throws<ArgumentNullException>(() => new JsonSecretsFileReadOnlyCache(FilePath, trust, null!, format));
        Assert.Throws<ArgumentNullException>(() => new JsonSecretsFileReadOnlyCache(FilePath, trust, ring, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new JsonSecretsFileReadOnlyCache(FilePath, trust, ring, format, maxFileLength: 0));
        Assert.Throws<FileNotFoundException>(() => new JsonSecretsFileReadOnlyCache(Path.Join(_dir.Path, "absent.json"), trust, ring, format));
        Assert.Equal(Path.GetFullPath(FilePath), new JsonSecretsFileReadOnlyCache(FilePath, trust, ring, format).FilePath);
    }

    [Fact]
    public async Task ANullName_Throws()
    {
        var ring = await NewRingAsync();
        Write(ring, ("item", "value"));
        var cache = CreateCache(ring);

        Assert.Throws<ArgumentNullException>(() => cache.Decrypt(null!, new byte[16]));
        Assert.Throws<ArgumentNullException>(() => cache.TryGetMaxDecryptedLength(null!, out _));
    }
}
