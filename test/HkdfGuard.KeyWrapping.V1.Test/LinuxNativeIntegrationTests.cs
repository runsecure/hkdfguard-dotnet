using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// The Linux native library's contract, through the verified loader and the binding, against the
/// real KEK provider - on a TPM host, provisioned by scripts/provision-linux-test-key.sh:
/// <code>
/// sudo scripts/provision-linux-test-key.sh
/// HKDFGUARD_TEST_SERVICE=com.hkdfguard.native.linux.test \
/// HKDFGUARD_TEST_SERVICE_OTHER=com.hkdfguard.native.linux.test.other \
/// dotnet test test/HkdfGuard.KeyWrapping.V1.Test
/// </code>
/// NativeKeyWrappingIntegrationTests covers what every platform shares; these pin down the exact
/// Linux status codes, the native library's own input checks (which .NET validation normally keeps
/// it from seeing), its zeroing on failure, and the deployment path through hkdfguard-v1-initialize.
/// </summary>
public class LinuxNativeIntegrationTests
{
    private const int DekLength = AbstractHkdfGuardKmsLibrary.DekLength;

    private static string Service => NativeTestEnvironment.ServiceName!;

    private static readonly LinuxHkdfGuardKmsLibrary Library = new();

    private static byte[] Wrap(byte[] dek, string? service = null)
    {
        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, Library.WrapDek(service ?? Service, dek, wrapped, out var written));
        return wrapped[..written];
    }

    private static void AssertStatus(int expected, int actual)
    {
        Assert.Equal(expected, actual);
        Assert.NotNull(Library.DescribeStatus(actual));
    }

    [LinuxNativeIntegrationFact]
    public void AWrappedDek_RoundTrips_AndFitsTheKeyFileLimit()
    {
        var dek = RandomNumberGenerator.GetBytes(DekLength);

        var wrapped = Wrap(dek);
        var recovered = new byte[DekLength];
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, Library.UnwrapDek(Service, wrapped, recovered, out var written));

        Assert.Equal(DekLength, written);
        Assert.Equal(dek, recovered);
        Assert.InRange(wrapped.Length, DekLength + 1, WrappedKeyLimits.MaxBytes);
    }

    [LinuxNativeIntegrationFact]
    public void WrappingTheSameDekTwice_GivesDifferentPayloads()
    {
        // A fresh salt per payload: equal DEKs must not be recognizable from their wrapped form.
        var dek = RandomNumberGenerator.GetBytes(DekLength);

        Assert.NotEqual(Wrap(dek), Wrap(dek));
    }

    [LinuxNativeIntegrationFact]
    public void GeneratedDeks_AreDistinct()
    {
        var deks = new List<byte[]>();
        for (var i = 0; i < 4; i++)
        {
            var wrapped = new byte[WrappedKeyLimits.MaxBytes];
            Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, Library.GenerateAndWrapDek(Service, wrapped, out var written));

            var dek = new byte[DekLength];
            Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, Library.UnwrapDek(Service, wrapped.AsSpan(0, written), dek, out _));
            deks.Add(dek);
        }

        Assert.Equal(deks.Count, deks.Select(Convert.ToHexString).Distinct().Count());
    }

    [LinuxNativeIntegrationFact(NeedsOtherService = true)]
    public void UnwrappingUnderAnotherProvisionedService_IsAFingerprintMismatch_AndZeroesTheWholeBuffer()
    {
        var wrapped = Wrap(RandomNumberGenerator.GetBytes(DekLength));
        var destination = Enumerable.Repeat((byte)0xAA, 64).ToArray();

        var status = Library.UnwrapDek(NativeTestEnvironment.OtherServiceName, wrapped, destination, out _);

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrFingerprintMismatch, status);
        Assert.All(destination, b => Assert.Equal(0, b));
    }

    [LinuxNativeIntegrationFact(NeedsPinnedNamesAllowlist = true)]
    public void AServiceTheAllowlistDoesNotName_HasNoKek()
    {
        var unlisted = NativeTestEnvironment.UnprovisionedServiceName;

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrKekNotFound, Library.WrapDek(unlisted, new byte[DekLength], new byte[WrappedKeyLimits.MaxBytes], out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrKekNotFound, Library.GenerateAndWrapDek(unlisted, new byte[WrappedKeyLimits.MaxBytes], out _));
        Assert.Contains("provision", Library.DescribeStatus(LinuxHkdfGuardKmsLibrary.ErrKekNotFound));
    }

    [LinuxNativeIntegrationFact]
    public void ChangingAnyByteOfThePayload_IsRefused_AndRevealsNothing()
    {
        // Every byte is either ciphertext or bound into the AEAD's associated data and the HKDF
        // info, so no single-byte change may unwrap - to the original DEK or to any other. Each
        // refusal can cost a TPM ECDH, so this changes the first and last eight bytes and every
        // fifth byte between: a spread that lands in every field of the payload.
        var wrapped = Wrap(RandomNumberGenerator.GetBytes(DekLength));
        var positions = Enumerable.Range(0, wrapped.Length)
            .Where(i => i < 8 || i >= wrapped.Length - 8 || i % 5 == 0);

        foreach (var i in positions)
        {
            var tampered = (byte[])wrapped.Clone();
            tampered[i] ^= 0x01;
            var destination = Enumerable.Repeat((byte)0xAA, DekLength).ToArray();

            var status = Library.UnwrapDek(Service, tampered, destination, out _);

            Assert.True(
                status is LinuxHkdfGuardKmsLibrary.ErrCryptoError or LinuxHkdfGuardKmsLibrary.ErrFingerprintMismatch,
                $"byte {i} of {wrapped.Length}: status {status}");
            Assert.All(destination, b => Assert.Equal(0, b));
        }
    }

    [LinuxNativeIntegrationFact]
    public void ATruncatedOrExtendedPayload_IsRefused()
    {
        var wrapped = Wrap(RandomNumberGenerator.GetBytes(DekLength));
        var destination = new byte[DekLength];

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrCryptoError, Library.UnwrapDek(Service, wrapped[..^1], destination, out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrCryptoError, Library.UnwrapDek(Service, [.. wrapped, 0], destination, out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrCryptoError, Library.UnwrapDek(Service, wrapped[..8], destination, out _));
    }

    [LinuxNativeIntegrationFact]
    public void AnEmptyPayload_IsRefused()
    {
        var status = Library.UnwrapDek(Service, ReadOnlySpan<byte>.Empty, new byte[DekLength], out _);

        Assert.True(status is LinuxHkdfGuardKmsLibrary.ErrInvalidArgument or LinuxHkdfGuardKmsLibrary.ErrCryptoError, $"status {status}");
    }

    [LinuxNativeIntegrationFact]
    public void ADekOfTheWrongLength_IsAnInvalidArgument()
    {
        foreach (var length in new[] { 0, 16, DekLength - 1, DekLength + 1, 64 })
            AssertStatus(LinuxHkdfGuardKmsLibrary.ErrInvalidArgument, Library.WrapDek(Service, new byte[length], new byte[WrappedKeyLimits.MaxBytes], out _));
    }

    public static TheoryData<string> InvalidServiceNames => new()
    {
        "",
        ".leading.dot",
        "double..dot",
        "has space",
        "slash/inside",
        "dash-inside",
        "café",
        new string('a', 129),
    };

    [LinuxNativeIntegrationTheory]
    [MemberData(nameof(InvalidServiceNames))]
    public void TheNativeLibrary_ChecksServiceNamesItself(string service)
    {
        // .NET's ServiceNames rule normally stops these before the boundary; the library must
        // refuse them on its own too, for every operation.
        Assert.False(ServiceNames.IsValid(service));

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrInvalidServiceName, Library.WrapDek(service, new byte[DekLength], new byte[WrappedKeyLimits.MaxBytes], out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrInvalidServiceName, Library.GenerateAndWrapDek(service, new byte[WrappedKeyLimits.MaxBytes], out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrInvalidServiceName, Library.UnwrapDek(service, new byte[100], new byte[DekLength], out _));
    }

    [LinuxNativeIntegrationFact]
    public void AServiceNameOfTheMaximumLength_IsAccepted()
    {
        // 128 characters is valid; with the allowlist it simply has no KEK, without one it may.
        var service = new string('a', ServiceNames.MaxLength);

        var status = Library.WrapDek(service, new byte[DekLength], new byte[WrappedKeyLimits.MaxBytes], out _);

        Assert.NotEqual(LinuxHkdfGuardKmsLibrary.ErrInvalidServiceName, status);
    }

    [LinuxNativeIntegrationFact]
    public void ATooSmallBuffer_ReportsACapacityThatSuffices()
    {
        // The reported capacity is an upper bound for any payload (276 bytes on 0.1.0, for a
        // 164-byte payload), not the exact size of this one; it must fit a key file and be enough.
        var dek = RandomNumberGenerator.GetBytes(DekLength);

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrBufferTooSmall, Library.WrapDek(Service, dek, new byte[1], out var required));
        Assert.InRange(required, DekLength + 1, WrappedKeyLimits.MaxBytes);

        var exact = new byte[required];
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, Library.WrapDek(Service, dek, exact, out var written));
        Assert.InRange(written, DekLength + 1, required);
        exact = exact[..written];

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrBufferTooSmall, Library.GenerateAndWrapDek(Service, new byte[1], out var generateRequired));
        Assert.Equal(required, generateRequired);

        var shortDestination = Enumerable.Repeat((byte)0xAA, DekLength - 1).ToArray();
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrBufferTooSmall, Library.UnwrapDek(Service, exact, shortDestination, out var unwrapRequired));
        Assert.Equal(DekLength, unwrapRequired);
        Assert.All(shortDestination, b => Assert.Equal(0, b));
    }

    [LinuxNativeIntegrationFact]
    public async Task ConcurrentCallers_EachGetTheirOwnDekBack()
    {
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            var dek = RandomNumberGenerator.GetBytes(DekLength);
            var recovered = new byte[DekLength];
            var status = Library.UnwrapDek(Service, Wrap(dek), recovered, out _);
            return (status, Same: dek.AsSpan().SequenceEqual(recovered));
        })));

        Assert.All(results, r =>
        {
            Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, r.status);
            Assert.True(r.Same);
        });
    }

    [LinuxNativeIntegrationFact(NeedsCli = true)]
    public async Task AKeyFileWrappedByTheProvisioningTool_RevealsItsDekThroughTheWrapper()
    {
        // The deployment path: hkdfguard-v1-initialize wraps a delivered DEK on the host, in its
        // own process, and the application unwraps the key file through this binding.
        var directory = Directory.CreateTempSubdirectory("hkdfguard-cli-");
        try
        {
            var dek = RandomNumberGenerator.GetBytes(DekLength);
            var dekFile = Path.Combine(directory.FullName, "dek");
            var keyFile = Path.Combine(directory.FullName, "key.bin");
            await using (var stream = new FileStream(dekFile, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(dek)));
            }

            var (exitCode, output) = await RunCliAsync("wrap", "--key-file-path", keyFile, "--service-name", Service, "--dek-file", dekFile);
            Assert.True(exitCode == 0, $"hkdfguard-v1-initialize wrap exited {exitCode}: {output}");
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyFile));

            var recovered = new byte[DekLength];
            var written = await new NativeHkdfKeyWrapperV1(Service).UnwrapAsync(await File.ReadAllBytesAsync(keyFile), recovered);

            Assert.Equal(DekLength, written);
            Assert.Equal(dek, recovered);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [LinuxNativeIntegrationFact(NeedsCli = true)]
    public async Task TheProvisioningTool_ReportsTheTestServiceAsProvisioned()
    {
        var (exitCode, output) = await RunCliAsync("provision", "--service-name", Service);

        Assert.True(exitCode == 0, $"hkdfguard-v1-initialize provision exited {exitCode}: {output}");
    }

    private static async Task<(int ExitCode, string Output)> RunCliAsync(params string[] arguments)
    {
        var start = new ProcessStartInfo(LinuxNativeIntegrationFactAttribute.Cli)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);

        return (process.ExitCode, await stdout + await stderr);
    }
}
