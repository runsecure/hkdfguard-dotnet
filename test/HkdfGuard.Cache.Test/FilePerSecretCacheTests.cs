using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache.Test.TestHelpers;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Diagnostics;
using HkdfGuard.SecureFile;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.Cache.Test;

/// <summary>FilePerSecretCache over a real folder TrustedFile accepts, with values written by a ring's protectors.</summary>
public sealed class FilePerSecretCacheTests : IDisposable
{
    private readonly TrustedTempDirectory _dir = new();

    private string Folder => _dir.Path;

    public void Dispose() => _dir.Dispose();

    private static async Task<IDataEncryptionKey> NewKeyAsync()
        => new HkdfGuard.DataEncryptionKey.DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(
            new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));

    private static async Task<KeyRing> NewRingAsync() => TestRing.For(await NewKeyAsync());

    private FilePerSecretCache CreateCache(IKeyRing ring) => new(Folder, _dir.Trust, ring, new DefaultFormatProvider());

    // Writes value to name's file, encrypted as a pipeline or deployer would: bound to that name.
    private void Write(KeyRing ring, string name, string value, string suffix = "")
        => File.WriteAllText(Path.Join(Folder, name), ring.CreateProtector(ProtectedConfigurationPurpose.For(name)).Encrypt(value) + suffix);

    private static string DecryptString(IProtectedReadOnlyCache cache, string name)
    {
        var result = new char[64];
        return new string(result, 0, cache.Decrypt(name, result.AsSpan()));
    }

    [Fact]
    public async Task AFile_DecryptsThroughEveryOverload()
    {
        var ring = await NewRingAsync();
        Write(ring, "Db-Password", "value");
        var cache = CreateCache(ring);

        Assert.Equal("value", DecryptString(cache, "Db-Password"));
        var bytes = new byte[16];
        Assert.Equal("value", Encoding.UTF8.GetString(bytes, 0, cache.Decrypt("Db-Password", bytes)));
        Assert.True(cache.TryGetMaxDecryptedLength("Db-Password", out var max));
        Assert.True(max >= 5);

        var chars = new char[16];
        Assert.Equal("value", new string(chars, 0, await cache.DecryptAsync("Db-Password", chars.AsMemory())));
        Assert.Equal("value", Encoding.UTF8.GetString(bytes, 0, await cache.DecryptAsync("Db-Password", bytes.AsMemory())));
        Assert.Equal(max, await cache.GetMaxDecryptedLengthAsync("Db-Password"));
    }

    [Fact]
    public async Task SurroundingWhitespace_IsIgnored()
    {
        var ring = await NewRingAsync();
        Write(ring, "item", "value", suffix: "\r\n");

        Assert.Equal("value", DecryptString(CreateCache(ring), "item"));
    }

    [Fact]
    public async Task AFile_IsReadOnce_ThenServedFromMemory()
    {
        var ring = await NewRingAsync();
        var cache = CreateCache(ring);
        Write(ring, "item", "first");
        Assert.Equal("first", DecryptString(cache, "item"));

        Write(ring, "item", "second");
        Assert.Equal("first", DecryptString(cache, "item"));
        File.Delete(Path.Join(Folder, "item"));
        Assert.Equal("first", DecryptString(cache, "item"));
        var chars = new char[16];
        Assert.Equal("first", new string(chars, 0, await cache.DecryptAsync("item", chars.AsMemory())));
    }

    [Fact]
    public async Task AChangedFile_IsPickedUpByANewInstance()
    {
        var ring = await NewRingAsync();
        Write(ring, "item", "first");
        Assert.Equal("first", DecryptString(CreateCache(ring), "item"));

        Write(ring, "item", "second");
        Assert.Equal("second", DecryptString(CreateCache(ring), "item"));
    }

    [Fact]
    public async Task AMissingSecret_IsntRemembered_SoAFileAddedLaterIsFound()
    {
        var ring = await NewRingAsync();
        var cache = CreateCache(ring);
        Assert.Equal(0, cache.Decrypt("item", new byte[16]));

        Write(ring, "item", "value");
        Assert.Equal("value", DecryptString(cache, "item"));
    }

    [Fact]
    public async Task AMissingOrEmptyFile_IsMissing()
    {
        var ring = await NewRingAsync();
        File.WriteAllText(Path.Join(Folder, "empty"), " \n");
        var cache = CreateCache(ring);

        foreach (var name in new[] { "absent", "empty" })
        {
            Assert.Equal(0, cache.Decrypt(name, new byte[16]));
            Assert.Equal(0, cache.Decrypt(name, new char[16]));
            Assert.False(cache.TryGetMaxDecryptedLength(name, out var max));
            Assert.Equal(0, max);
            Assert.Equal(0, await cache.DecryptAsync(name, new byte[16].AsMemory()));
            Assert.Equal(0, await cache.DecryptAsync(name, new char[16].AsMemory()));
            Assert.Equal(0, await cache.GetMaxDecryptedLengthAsync(name));
        }
    }

    [Fact]
    public async Task AFolderRemovedAfterConstruction_ReportsEverySecretMissing()
    {
        var ring = await NewRingAsync();
        Write(ring, "item", "value");
        var cache = CreateCache(ring);
        Directory.Delete(Folder, recursive: true);

        Assert.Equal(0, cache.Decrypt("item", new byte[16]));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".hidden")]
    [InlineData("..")]
    [InlineData("../item")]
    [InlineData("sub/item")]
    [InlineData(@"sub\item")]
    [InlineData("db:password")]
    [InlineData("café")]
    public async Task ANameThatCantBeAFileName_IsMissing_WithoutReadingOutsideTheFolder(string name)
    {
        var ring = await NewRingAsync();
        Directory.CreateDirectory(Path.Join(Folder, "sub"));
        Write(ring, "item", "value");
        var cache = new FilePerSecretCache(Path.Join(Folder, "sub"), _dir.Trust, ring, new DefaultFormatProvider());

        Assert.False(FilePerSecretCache.IsValidName(name));
        Assert.Equal(0, cache.Decrypt(name, new byte[16]));
        Assert.Equal(0, await cache.DecryptAsync(name, new char[16].AsMemory()));
    }

    [Fact]
    public void IsValidName_AcceptsUpToMaxNameLength_OfLettersDigitsAndPunctuation()
    {
        Assert.True(FilePerSecretCache.IsValidName("Db-Password_v2.txt"));
        Assert.True(FilePerSecretCache.IsValidName(new string('a', FilePerSecretCache.MaxNameLength)));
        Assert.False(FilePerSecretCache.IsValidName(new string('a', FilePerSecretCache.MaxNameLength + 1)));
        Assert.False(FilePerSecretCache.IsValidName(null));
    }

    [Fact]
    public async Task AFileCopiedUnderAnotherName_FailsAuthentication()
    {
        var ring = await NewRingAsync();
        Write(ring, "admin", "secret");
        File.Copy(Path.Join(Folder, "admin"), Path.Join(Folder, "reader"));
        var cache = CreateCache(ring);

        Assert.ThrowsAny<CryptographicException>(() => cache.Decrypt("reader", new byte[16]));
        Assert.ThrowsAny<CryptographicException>(() => cache.Decrypt("reader", new char[16]));
        Assert.ThrowsAny<CryptographicException>(() => cache.TryGetMaxDecryptedLength("reader", out _));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await cache.DecryptAsync("reader", new byte[16].AsMemory()));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await cache.DecryptAsync("reader", new char[16].AsMemory()));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await cache.GetMaxDecryptedLengthAsync("reader"));
    }

    [Fact]
    public async Task AFileThatFailsAuthentication_IsntCached_SoAFixedFileIsReadNextTime()
    {
        var ring = await NewRingAsync();
        Write(ring, "admin", "secret");
        File.Copy(Path.Join(Folder, "admin"), Path.Join(Folder, "reader"));
        var cache = CreateCache(ring);
        Assert.ThrowsAny<CryptographicException>(() => cache.Decrypt("reader", new byte[16]));

        Write(ring, "reader", "fixed");
        Assert.Equal("fixed", DecryptString(cache, "reader"));
    }

    [Fact]
    public async Task AFileInAnUntrustedLocation_IsRefused_AndNotCached()
    {
        if (!OperatingSystem.IsWindows() && Environment.UserName == "root")
            return; // root's files are trusted

        var ring = await NewRingAsync();
        Write(ring, "item", "value");
        var untrusted = new FilePerSecretCache(Folder, KeyFileTrust.AdministratorsOnly, ring, new DefaultFormatProvider());

        Assert.Throws<UnauthorizedAccessException>(() => untrusted.Decrypt("item", new byte[16]));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await untrusted.DecryptAsync("item", new byte[16].AsMemory()));
        Assert.Equal("value", DecryptString(CreateCache(ring), "item"));
    }

    [Fact]
    public async Task AValueUnderAnOlderKeyVersion_StillDecryptsAfterRotation()
    {
        var ring = await NewRingAsync();
        Write(ring, "item", "old");
        ring.Add(2, await NewKeyAsync());
        Write(ring, "other", "new");
        var cache = CreateCache(ring);

        Assert.Equal("old", DecryptString(cache, "item"));
        Assert.Equal("new", DecryptString(cache, "other"));
    }

    [Fact]
    public async Task AValueUnderAKeyVersionTheRingDoesntHold_Throws()
    {
        var ring = await NewRingAsync();
        File.WriteAllText(Path.Join(Folder, "item"), new DefaultFormatProvider().Format(
            new KeyTrackingValue { KeyVersion = 7, Value = RandomNumberGenerator.GetBytes(40) }));

        Assert.Throws<KeyNotFoundException>(() => CreateCache(ring).Decrypt("item", new byte[64]));
    }

    [Fact]
    public async Task AFileOverMaxFileLength_IsRefused()
    {
        var ring = await NewRingAsync();
        File.WriteAllBytes(Path.Join(Folder, "huge"), new byte[FilePerSecretCache.MaxFileLength + 1]);
        var cache = CreateCache(ring);

        Assert.Throws<InvalidDataException>(() => cache.Decrypt("huge", new byte[16]));
        await Assert.ThrowsAsync<InvalidDataException>(async () => await cache.GetMaxDecryptedLengthAsync("huge"));
    }

    [Fact]
    public async Task ALargeValue_DecryptsAsCharacters_ThroughAPinnedBuffer()
    {
        // Over the default format's limit, so ring and cache both allow longer values.
        var format = new DefaultFormatProvider(maxEncryptedLength: 16 * 1024);
        var ring = new KeyRing(format);
        ring.Add(1, await NewKeyAsync());
        var value = new string('x', ArrayUtility.MaxStackBytes + 10);
        Write(ring, "large", value);
        var cache = new FilePerSecretCache(Folder, _dir.Trust, ring, format);

        var result = new char[value.Length];
        Assert.Equal(value.Length, cache.Decrypt("large", result.AsSpan()));
        Assert.Equal(value, new string(result));
    }

    [Fact]
    public async Task ACancelledToken_Throws()
    {
        var cache = CreateCache(await NewRingAsync());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await cache.DecryptAsync("item", new byte[16].AsMemory(), new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task SensitiveLogging_DoesntChangeTheResult()
    {
        var ring = await NewRingAsync();
        Write(ring, "item", "value");
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

        Assert.Throws<ArgumentNullException>(() => new FilePerSecretCache(null!, trust, ring, format));
        Assert.Throws<ArgumentException>(() => new FilePerSecretCache("", trust, ring, format));
        Assert.Throws<ArgumentNullException>(() => new FilePerSecretCache(Folder, null!, ring, format));
        Assert.Throws<ArgumentNullException>(() => new FilePerSecretCache(Folder, trust, null!, format));
        Assert.Throws<ArgumentNullException>(() => new FilePerSecretCache(Folder, trust, ring, null!));
        Assert.Throws<DirectoryNotFoundException>(() => new FilePerSecretCache(Path.Join(Folder, "absent"), trust, ring, format));
        Assert.Equal(Path.GetFullPath(Folder), new FilePerSecretCache(Folder, _dir.Trust, ring, format).FolderPath);
    }

    [Fact]
    public async Task ANullName_Throws()
    {
        var cache = CreateCache(await NewRingAsync());

        Assert.Throws<ArgumentNullException>(() => cache.Decrypt(null!, new byte[16]));
        Assert.Throws<ArgumentNullException>(() => cache.TryGetMaxDecryptedLength(null!, out _));
    }
}
