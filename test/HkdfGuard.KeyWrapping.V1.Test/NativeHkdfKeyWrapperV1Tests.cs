using HkdfGuard.Abstractions;
using System.Security.Cryptography;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class NativeHkdfKeyWrapperV1Tests
{
    [Fact]
    public void Constructor_WithServiceName_InstantiatesSuccessfully()
    {
        var wrapper = new NativeHkdfKeyWrapperV1("test.service");

        Assert.NotNull(wrapper);
    }

    [Fact]
    public async Task WrapAsync_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            WrapPayloadToEmit = new byte[] { 10, 20, 30, 40 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.a", fakeLibrary);

        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var resultBuffer = new byte[16];

        var bytesWritten = await wrapper.WrapAsync(plaintext, resultBuffer);

        Assert.Equal(4, bytesWritten);
        Assert.Equal(1, fakeLibrary.WrapCallCount);
        Assert.Equal("service.a", fakeLibrary.LastService);
        Assert.Equal(plaintext, fakeLibrary.LastWrapPlaintext);
        Assert.Equal(new byte[] { 10, 20, 30, 40 }, resultBuffer[..4]);
    }

    [Theory]
    [InlineData(-7)]  // reserved codes: no platform returns them, so there is no meaning to add
    [InlineData(-14)]
    [InlineData(-40)]
    public async Task WrapAsync_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            WrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.d", fakeLibrary);

        var plaintext = new byte[] { 1, 2, 3 };
        var resultBuffer = new byte[8];

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.WrapAsync(plaintext, resultBuffer));

        Assert.Equal($"Native KMS wrap failed for service 'service.d' with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.WrapCallCount);
    }

    [Fact]
    public async Task AFailure_TheLibraryCanDescribe_NamesWhatTheStatusMeans()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapDekStatus = -13,
            Describe = status => status == -13 ? "this account is not authorized to use the KEK" : null,
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.d", fakeLibrary);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[] { 1 }, new byte[32]));

        Assert.Equal("Native KMS unwrap failed for service 'service.d' with status -13 (this account is not authorized to use the KEK).", exception.Message);
    }

    [Fact]
    public async Task UnwrapAsync_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapPayloadToEmit = new byte[] { 1, 2, 3, 4, 5 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.a", fakeLibrary);

        var wrapped = new byte[] { 10, 20, 30, 40 };
        var resultBuffer = new byte[16];

        var bytesWritten = await wrapper.UnwrapAsync(wrapped, resultBuffer);

        Assert.Equal(5, bytesWritten);
        Assert.Equal(1, fakeLibrary.UnwrapCallCount);
        Assert.Equal("service.a", fakeLibrary.LastService);
        Assert.Equal(wrapped, fakeLibrary.LastUnwrapWrapped);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, resultBuffer[..5]);
    }

    [Theory]
    [InlineData(-7)]  // reserved codes: no platform returns them, so there is no meaning to add
    [InlineData(-14)]
    [InlineData(-40)]
    public async Task UnwrapAsync_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.d", fakeLibrary);

        var wrapped = new byte[] { 10, 20, 30 };
        var resultBuffer = Enumerable.Repeat((byte)0xFF, 8).ToArray();

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped, resultBuffer));

        Assert.Equal($"Native KMS unwrap failed for service 'service.d' with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.UnwrapCallCount);
        // Whatever the native call left in the DEK buffer before failing is gone.
        Assert.All(resultBuffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task GenerateAndWrapAsync_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            GenerateAndWrapPayloadToEmit = new byte[] { 11, 22, 33, 44, 55 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.e", fakeLibrary);

        var resultBuffer = new byte[16];

        var bytesWritten = await wrapper.GenerateAndWrapAsync(resultBuffer);

        Assert.Equal(5, bytesWritten);
        Assert.Equal(1, fakeLibrary.GenerateAndWrapCallCount);
        Assert.Equal("service.e", fakeLibrary.LastService);
        Assert.Equal(new byte[] { 11, 22, 33, 44, 55 }, resultBuffer[..5]);
    }

    [Theory]
    [InlineData(-7)]  // reserved codes: no platform returns them, so there is no meaning to add
    [InlineData(-14)]
    [InlineData(-40)]
    public async Task GenerateAndWrapAsync_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            GenerateAndWrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.f", fakeLibrary);

        var resultBuffer = new byte[16];

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(resultBuffer));

        Assert.Equal($"Native KMS generate-and-wrap failed for service 'service.f' with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.GenerateAndWrapCallCount);
    }

    [Fact]
    public async Task WrapAsync_WhenCancelled_DoesNotCallLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.WrapAsync(new byte[32], new byte[64], new CancellationToken(true)));

        Assert.Equal(0, fakeLibrary.WrapCallCount);
    }

    [Fact]
    public async Task UnwrapAsync_WhenCancelled_DoesNotCallLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.UnwrapAsync(new byte[64], new byte[32], new CancellationToken(true)));

        Assert.Equal(0, fakeLibrary.UnwrapCallCount);
    }

    [Fact]
    public async Task GenerateAndWrapAsync_WhenCancelled_DoesNotCallLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[64], new CancellationToken(true)));

        Assert.Equal(0, fakeLibrary.GenerateAndWrapCallCount);
    }

    // A successful call reporting a count outside the buffer broke the native contract: the
    // result is refused and whatever the call left in the buffer is zeroed.

    [Theory]
    [InlineData(-1)]
    [InlineData(17)]
    public async Task WrapAsync_WhenTheLibraryReportsACountOutsideTheBuffer_ThrowsAndZeroesIt(int reported)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary { WrapDekBytesWrittenOverride = reported };
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);
        var resultBuffer = new byte[16];

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.WrapAsync(new byte[] { 1, 2, 3 }, resultBuffer));

        Assert.Equal($"Native KMS wrap for service 'service.g' reported {reported} bytes written into a 16-byte buffer; the result was discarded.", exception.Message);
        Assert.All(resultBuffer, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(33)]
    public async Task UnwrapAsync_WhenTheLibraryReportsACountOutsideTheBuffer_ThrowsAndZeroesIt(int reported)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapPayloadToEmit = Enumerable.Repeat((byte)0xFF, 32).ToArray(),
            UnwrapDekBytesWrittenOverride = reported,
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);
        var resultBuffer = new byte[32];

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[] { 1 }, resultBuffer));

        Assert.Contains($"reported {reported} bytes written into a 32-byte buffer", exception.Message);
        Assert.All(resultBuffer, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(17)]
    public async Task GenerateAndWrapAsync_WhenTheLibraryReportsACountOutsideTheBuffer_ThrowsAndZeroesIt(int reported)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            GenerateAndWrapPayloadToEmit = Enumerable.Repeat((byte)0xFF, 16).ToArray(),
            GenerateAndWrapDekBytesWrittenOverride = reported,
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);
        var resultBuffer = new byte[16];

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(resultBuffer));

        Assert.Contains($"generate-and-wrap for service 'service.g' reported {reported} bytes", exception.Message);
        Assert.All(resultBuffer, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    public async Task UnwrapAsync_ACountAtEitherEndOfTheBuffer_IsAccepted(int reported)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapPayloadToEmit = new byte[32],
            UnwrapDekBytesWrittenOverride = reported,
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service.g", fakeLibrary);

        Assert.Equal(reported, await wrapper.UnwrapAsync(new byte[] { 1 }, new byte[32]));
    }

    [Fact]
    public async Task AFailure_NamesTheStatusAndItsSharedMeaning()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary { UnwrapDekStatus = AbstractHkdfGuardKmsLibrary.ErrKekNotFound };
        var wrapper = new NativeHkdfKeyWrapperV1("service.d", fakeLibrary);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(new byte[] { 1 }, new byte[32]));

        Assert.Equal("Native KMS unwrap failed for service 'service.d' with status -17 "
            + "(no KEK is provisioned for this service; run hkdfguard provision).", exception.Message);
    }

    [Fact]
    public async Task ReadKeyFileAsync_ReadsThroughTheNativeLibrary_NotDotNetFileIo()
    {
        var payload = Enumerable.Range(0, 132).Select(i => (byte)i).ToArray();
        var fakeLibrary = new FakeHkdfGuardKmsLibrary { OpenFilePayloadToEmit = payload };
        var wrapper = new NativeHkdfKeyWrapperV1("service.h", fakeLibrary);

        // The path doesn't exist: only the native library is asked about it.
        var read = await wrapper.ReadKeyFileAsync(@"C:\no\such\dek.bin");

        Assert.Equal(payload, read);
        Assert.Equal(1, fakeLibrary.OpenFileCallCount);
        Assert.Equal(@"C:\no\such\dek.bin", fakeLibrary.LastOpenFilePath);
    }

    [Fact]
    public async Task ReadKeyFileAsync_ThroughTheInterface_ReachesTheNativeLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary();
        IKeyWrapper wrapper = new NativeHkdfKeyWrapperV1("service.h", fakeLibrary);

        await wrapper.ReadKeyFileAsync("dek.bin");

        Assert.Equal(1, fakeLibrary.OpenFileCallCount);
    }

    [Fact]
    public async Task ReadKeyFileAsync_SurfacesARefusalThroughTheReturnedTask()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary { OpenFileStatus = AbstractHkdfGuardKmsLibrary.ErrFilePlaintextKey };
        var wrapper = new NativeHkdfKeyWrapperV1("service.h", fakeLibrary);

        var read = wrapper.ReadKeyFileAsync("dek.bin");

        Assert.True(read.IsFaulted);
        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await read);
        Assert.Contains("key exposure", thrown.Message);
    }

    [Fact]
    public async Task ReadKeyFileAsync_WhenCancelled_DoesNotCallLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1("service.h", fakeLibrary);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.ReadKeyFileAsync("dek.bin", new CancellationToken(true)));

        Assert.Equal(0, fakeLibrary.OpenFileCallCount);
    }
}
