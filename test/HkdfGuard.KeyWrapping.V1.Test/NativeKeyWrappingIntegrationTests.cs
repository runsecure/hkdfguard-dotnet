using System.Security.Cryptography;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Real key wrapping and unwrapping against this platform's native KMS library (Windows Platform
/// Crypto Provider / TPM, Linux TPM2/keyring/OpenSSL, macOS Secure Enclave). No native library
/// creates a KEK during wrap/unwrap, so these run against an operator-provisioned service:
/// <code>
/// hkdfguard-v1-initialize provision --service-name hkdfguard.integrationtest   (elevated on Windows)
/// HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest dotnet test
/// </code>
/// Without HKDFGUARD_TEST_SERVICE every test here is reported as skipped - never as passed. With it,
/// a library that is missing, fails verification, or misbehaves fails the run. The tests only use
/// that service's existing KEK; they never create or delete one.
/// </summary>
public class NativeKeyWrappingIntegrationTests
{
    private static string Service => NativeTestEnvironment.ServiceName!;

    [NativeIntegrationFact]
    public async Task NativeHkdfKeyWrapperV1_EncryptAndDecrypt_RoundTrips32ByteDek()
    {
        var wrapper = new NativeHkdfKeyWrapperV1(Service);

        var originalDek = RandomNumberGenerator.GetBytes(32);
        var wrapped = new byte[512];
        var wrappedBytesWritten = await wrapper.WrapAsync(originalDek, wrapped);

        Assert.True(wrappedBytesWritten > 0);
        Assert.False(wrapped.AsSpan(0, wrappedBytesWritten).SequenceEqual(originalDek));

        var unwrappedDek = new byte[32];
        var unwrappedBytesWritten = await wrapper.UnwrapAsync(wrapped.AsMemory(0, wrappedBytesWritten), unwrappedDek);

        Assert.Equal(32, unwrappedBytesWritten);
        Assert.Equal(originalDek, unwrappedDek);
    }

    [NativeIntegrationFact]
    public async Task NativeHkdfKeyWrapperV1_GenerateAndWrapAndDecrypt_ProducesValid32ByteDek()
    {
        var wrapper = new NativeHkdfKeyWrapperV1(Service);

        var wrapped = new byte[512];
        var wrappedBytesWritten = await wrapper.GenerateAndWrapAsync(wrapped);

        Assert.True(wrappedBytesWritten > 0);

        var recoveredDek1 = new byte[32];
        var unwrappedBytes1 = await wrapper.UnwrapAsync(wrapped.AsMemory(0, wrappedBytesWritten), recoveredDek1);

        Assert.Equal(32, unwrappedBytes1);
        Assert.False(recoveredDek1.All(b => b == 0));

        var recoveredDek2 = new byte[32];
        var unwrappedBytes2 = await wrapper.UnwrapAsync(wrapped.AsMemory(0, wrappedBytesWritten), recoveredDek2);

        Assert.Equal(32, unwrappedBytes2);
        Assert.Equal(recoveredDek1, recoveredDek2);
    }

    [NativeIntegrationFact]
    public async Task NativeHkdfKeyWrapperV1_ServiceIsolation_CannotDecryptPayloadFromDifferentService()
    {
        // A second provisioned service exercises the "wrong KEK" path; without one, an
        // unprovisioned name exercises "no KEK". Either way the unwrap must fail and reveal nothing.
        var wrapperA = new NativeHkdfKeyWrapperV1(Service);
        var wrapperB = new NativeHkdfKeyWrapperV1(NativeTestEnvironment.OtherServiceName);

        var wrapped = new byte[512];
        var wrappedLen = await wrapperA.WrapAsync(RandomNumberGenerator.GetBytes(32), wrapped);

        var destination = new byte[32];
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapperB.UnwrapAsync(wrapped.AsMemory(0, wrappedLen), destination));
        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [NativeIntegrationFact]
    public async Task NativeHkdfKeyWrapperV1_MultipleKeysUnderSameService_WrapAndUnwrapIndependently()
    {
        var wrapper = new NativeHkdfKeyWrapperV1(Service);

        var dek1 = RandomNumberGenerator.GetBytes(32);
        var dek2 = RandomNumberGenerator.GetBytes(32);

        var wrapped1 = new byte[512];
        var wrapped2 = new byte[512];

        var len1 = await wrapper.WrapAsync(dek1, wrapped1);
        var len2 = await wrapper.WrapAsync(dek2, wrapped2);

        var recovered1 = new byte[32];
        var recovered2 = new byte[32];

        var recoveredLen1 = await wrapper.UnwrapAsync(wrapped1.AsMemory(0, len1), recovered1);
        var recoveredLen2 = await wrapper.UnwrapAsync(wrapped2.AsMemory(0, len2), recovered2);

        Assert.Equal(32, recoveredLen1);
        Assert.Equal(32, recoveredLen2);
        Assert.Equal(dek1, recovered1);
        Assert.Equal(dek2, recovered2);
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_DirectWrapAndUnwrap_ReturnsOkStatusAndRecoversDek()
    {
        var library = NativeHost.Library;
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(Service, dek.AsSpan(), wrapped, out var bytesWritten);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);
        Assert.True(bytesWritten > 0);

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(Service, wrapped[..bytesWritten], recovered, out var unwrapBytes);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, unwrapStatus);
        Assert.Equal(32, unwrapBytes);
        Assert.Equal(dek, recovered.ToArray());
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_DirectGenerateAndWrapDek_ReturnsOkStatusAndProducesValidPayload()
    {
        var library = NativeHost.Library;

        Span<byte> wrapped = stackalloc byte[512];
        var genStatus = library.GenerateAndWrapDek(Service, wrapped, out var bytesWritten);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, genStatus);
        Assert.True(bytesWritten > 0);

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(Service, wrapped[..bytesWritten], recovered, out var unwrapBytes);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, unwrapStatus);
        Assert.Equal(32, unwrapBytes);
        Assert.False(recovered.ToArray().All(b => b == 0));
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_WrapDek_WithInsufficientBuffer_ReturnsError()
    {
        var library = NativeHost.Library;
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> tinyBuffer = stackalloc byte[1];
        var status = library.WrapDek(Service, dek.AsSpan(), tinyBuffer, out var requiredBytes);

        Assert.True(status < 0);
        Assert.True(requiredBytes > 1);
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_UnwrapDek_WithInsufficientBuffer_ReturnsError()
    {
        var library = NativeHost.Library;
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(Service, dek.AsSpan(), wrapped, out var bytesWritten);
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);

        Span<byte> tinyDestination = stackalloc byte[1];
        var status = library.UnwrapDek(Service, wrapped[..bytesWritten], tinyDestination, out _);

        Assert.True(status < 0);
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_GenerateAndWrapDek_WithInsufficientBuffer_ReturnsError()
    {
        var library = NativeHost.Library;

        Span<byte> tinyBuffer = stackalloc byte[1];
        var status = library.GenerateAndWrapDek(Service, tinyBuffer, out _);

        Assert.True(status < 0);
    }

    [NativeIntegrationFact]
    public void NativeHostLibrary_UnwrapDek_WithCorruptedPayload_ReturnsError()
    {
        var library = NativeHost.Library;
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(Service, dek.AsSpan(), wrapped, out var bytesWritten);
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);

        wrapped[0] ^= 0xFF;
        wrapped[bytesWritten / 2] ^= 0xFF;

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(Service, wrapped[..bytesWritten], recovered, out _);

        Assert.True(unwrapStatus < 0);
    }
}
