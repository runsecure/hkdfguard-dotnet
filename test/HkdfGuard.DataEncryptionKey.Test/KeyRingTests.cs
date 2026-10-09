using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class KeyRingTests
{
    private static async Task<IDataEncryptionKey> CreateFakeKeyAsync()
        => new DataEncryptionKey(await AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)), "wrapped"u8.ToArray(), 60));

    [Fact]
    public void CurrentVersion_BeforeAnyAdd_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<InvalidOperationException>(() => ring.CurrentVersion);
    }

    [Fact]
    public async Task Add_FirstKey_BecomesCurrentVersion()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public async Task Add_HigherVersion_BecomesNewCurrent()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());
        ring.Add(5, await CreateFakeKeyAsync());

        Assert.Equal(5, ring.CurrentVersion);
    }

    [Fact]
    public async Task Add_LowerVersionAfterHigher_DoesNotChangeCurrent()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(5, await CreateFakeKeyAsync());
        ring.Add(1, await CreateFakeKeyAsync());

        Assert.Equal(5, ring.CurrentVersion);
    }

    [Fact]
    public async Task Add_WithSensitiveLoggingEnabled_StillWorksCorrectly()
    {
        using var _ = new SensitiveLoggingScope(true);

        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public async Task Add_DuplicateVersion_ThrowsArgumentException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        var duplicate = await CreateFakeKeyAsync();
        Assert.Throws<ArgumentException>(() => ring.Add(1, duplicate));
    }

    [Fact]
    public async Task Get_RegisteredVersion_ReturnsSameInstance()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = await CreateFakeKeyAsync();
        ring.Add(1, key);

        Assert.Same(key, ring.Get(1));
    }

    [Fact]
    public void Get_UnregisteredVersion_ThrowsKeyNotFoundException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<KeyNotFoundException>(() => ring.Get(999));
    }

    [Fact]
    public async Task TryGet_RegisteredVersion_ReturnsTrueAndKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = await CreateFakeKeyAsync();
        ring.Add(1, key);

        Assert.True(ring.TryGet(1, out var found));
        Assert.Same(key, found);
    }

    [Fact]
    public void TryGet_UnregisteredVersion_ReturnsFalse()
    {
        var ring = new KeyRing(new DefaultFormatProvider());

        Assert.False(ring.TryGet(999, out var found));
        Assert.Null(found);
    }

    [Fact]
    public async Task GetCurrent_ReturnsCurrentVersionAndKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var key = await CreateFakeKeyAsync();
        ring.Add(3, key);

        var (version, resolvedKey) = ring.GetCurrent();

        Assert.Equal(3, version);
        Assert.Same(key, resolvedKey);
    }

    [Fact]
    public void GetCurrent_WithNoKeysAdded_ThrowsInvalidOperationException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        Assert.Throws<InvalidOperationException>(() => ring.GetCurrent());
    }

    [Fact]
    public async Task CreateProtector_ProducesWorkingProtectorBoundToThisRing()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        var protector = ring.CreateProtector("purpose");
        var formatted = protector.Encrypt("hello".AsSpan());

        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public async Task CreateProtector_UsesRingsConfiguredFormatProvider()
    {
        var recordingFormatProvider = new RecordingFormatProvider();
        var ring = new KeyRing(recordingFormatProvider);
        ring.Add(1, await CreateFakeKeyAsync());

        var formatted = ring.CreateProtector("purpose").Encrypt("hello".AsSpan());
        Assert.True(recordingFormatProvider.FormatCalled);

        ring.CreateProtector("purpose").Decrypt(formatted.AsSpan(), new char[16]);
        Assert.True(recordingFormatProvider.ParseCalled);
    }

    [Fact]
    public async Task Dispose_DisposesEveryRegisteredKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var first = await CreateFakeKeyAsync();
        var second = await CreateFakeKeyAsync();
        ring.Add(1, first);
        ring.Add(2, second);

        ring.Dispose();

        Assert.Throws<ObjectDisposedException>(() => first.Encrypt("value"u8.ToArray()));
        Assert.Throws<ObjectDisposedException>(() => second.Encrypt("value"u8.ToArray()));
    }

    [Fact]
    public void Dispose_LeavesKeysThatAreNotDisposableAlone()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, new NonDisposableKey());

        ring.Dispose();
    }

    [Fact]
    public async Task Dispose_CalledTwice_DoesNotThrow()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        ring.Dispose();
        ring.Dispose();
    }

    [Fact]
    public async Task Add_AfterDispose_ThrowsObjectDisposedException()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Dispose();

        var late = await CreateFakeKeyAsync();
        Assert.Throws<ObjectDisposedException>(() => ring.Add(1, late));
    }

    [Fact]
    public async Task Add_WhenRejected_LeavesOwnershipWithTheCaller()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());
        var rejected = await CreateFakeKeyAsync();

        Assert.Throws<ArgumentException>(() => ring.Add(1, rejected));
        ring.Dispose();

        Assert.NotEmpty(rejected.Encrypt("value"u8.ToArray()));
    }

    [Fact]
    public async Task DisposeAsync_DisposesEveryKind_OfRegisteredKey()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        var asyncDisposable = await CreateFakeKeyAsync();
        var syncOnly = new SyncOnlyDisposableKey();
        ring.Add(1, asyncDisposable);
        ring.Add(2, syncOnly);
        ring.Add(3, new NonDisposableKey());

        await ring.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => asyncDisposable.Encrypt("value"u8.ToArray()));
        Assert.True(syncOnly.Disposed);
    }

    [Fact]
    public async Task DisposeAsync_CalledTwiceOrAfterDispose_DoesNotThrow()
    {
        var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        await ring.DisposeAsync();
        await ring.DisposeAsync();
        ring.Dispose();

        var late = await CreateFakeKeyAsync();
        Assert.Throws<ObjectDisposedException>(() => ring.Add(2, late));
    }

    private sealed class SyncOnlyDisposableKey : IDataEncryptionKey, IDisposable
    {
        public bool Disposed { get; private set; }
        public byte[] Encrypt(Span<byte> plaintext) => [];
        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad) => [];
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => 0;
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => 0;
        public void Dispose() => Disposed = true;
    }

    private sealed class NonDisposableKey : IDataEncryptionKey
    {
        public byte[] Encrypt(Span<byte> plaintext) => [];
        public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad) => [];
        public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result) => 0;
        public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result) => 0;
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task CreateProtector_WithAnEmptyName_Throws(string? name)
    {
        using var ring = new KeyRing(new DefaultFormatProvider());
        ring.Add(1, await CreateFakeKeyAsync());

        Assert.ThrowsAny<ArgumentException>(() => ring.CreateProtector(name!));
    }
}
