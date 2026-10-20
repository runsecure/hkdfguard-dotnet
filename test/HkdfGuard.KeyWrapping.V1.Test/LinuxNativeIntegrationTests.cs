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
/// HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
/// dotnet test test/HkdfGuard.KeyWrapping.V1.Test
/// </code>
/// NativeKeyWrappingIntegrationTests covers what every platform shares; these pin down the exact
/// Linux status codes, the native library's own input checks (which .NET validation normally keeps
/// it from seeing), its zeroing on failure, and the deployment path through hkdfguard.
/// </summary>
public class LinuxNativeIntegrationTests
{
    private const int DekLength = AbstractHkdfGuardKmsLibrary.DekLength;

    private static string Service => NativeTestEnvironment.ProvisionedService;

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

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrKekFingerprintMismatch, status);
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

            // A changed header byte makes the payload malformed or of an unknown version; a changed
            // fingerprint routes it to no KEK; anything else fails authentication.
            Assert.True(
                status is LinuxHkdfGuardKmsLibrary.ErrPayloadAuthFailed or LinuxHkdfGuardKmsLibrary.ErrPayloadMalformed
                    or LinuxHkdfGuardKmsLibrary.ErrPayloadUnsupported or LinuxHkdfGuardKmsLibrary.ErrKekFingerprintMismatch,
                $"byte {i} of {wrapped.Length}: status {status}");
            Assert.All(destination, b => Assert.Equal(0, b));
        }
    }

    [LinuxNativeIntegrationFact]
    public void ATruncatedOrExtendedPayload_IsRefused()
    {
        var wrapped = Wrap(RandomNumberGenerator.GetBytes(DekLength));
        var destination = new byte[DekLength];

        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrPayloadMalformed, Library.UnwrapDek(Service, wrapped[..^1], destination, out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrPayloadMalformed, Library.UnwrapDek(Service, [.. wrapped, 0], destination, out _));
        AssertStatus(LinuxHkdfGuardKmsLibrary.ErrPayloadMalformed, Library.UnwrapDek(Service, wrapped[..8], destination, out _));
    }

    [LinuxNativeIntegrationFact]
    public void AnEmptyPayload_IsRefused()
    {
        var status = Library.UnwrapDek(Service, ReadOnlySpan<byte>.Empty, new byte[DekLength], out _);

        Assert.True(status is LinuxHkdfGuardKmsLibrary.ErrInvalidArgument or LinuxHkdfGuardKmsLibrary.ErrPayloadMalformed, $"status {status}");
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
        // The reported capacity is an upper bound for any payload (276 bytes on 0.9.0, for a
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

    // --- Key files, read through hkdfguard_open_file -------------------------------------------

    /// <summary>Runs <paramref name="test"/> with a fresh private key file folder and one real wrapped payload.</summary>
    private static async Task WithKeyFileFolderAsync(Func<string, byte[], Task> test)
    {
        var directory = TestDirectories.CreateKeyFileDirectory("hkdfguard-open-");
        try
        {
            await test(directory, Wrap(RandomNumberGenerator.GetBytes(DekLength)));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<string> WriteAsync(string directory, string name, byte[] contents)
    {
        var path = Path.Combine(directory, name);
        await TestDirectories.WriteKeyFileAsync(path, contents);
        return path;
    }

    private static readonly NativeHkdfKeyWrapperV1 Reader = new("hkdfguard.keyfile.reader");

    private static async Task<T> RefusedAsync<T>(string path, int status) where T : Exception
    {
        var thrown = await Assert.ThrowsAsync<T>(async () => await Reader.ReadKeyFileAsync(path));
        Assert.Contains($"status {status} (", thrown.Message);
        return thrown;
    }

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public Task AKeyFile_ReadsBackExactlyAsWritten()
        => WithKeyFileFolderAsync(async (directory, wrapped) =>
            Assert.Equal(wrapped, await Reader.ReadKeyFileAsync(await WriteAsync(directory, "key.bin", wrapped))));

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public Task AKeyFileOfTheWrongSize_IsRefused_AsTooShortOrTooLong()
        => WithKeyFileFolderAsync(async (directory, wrapped) =>
        {
            foreach (var (size, status) in new[]
                     {
                         (0, AbstractHkdfGuardKmsLibrary.ErrFileTooShort),
                         (100, AbstractHkdfGuardKmsLibrary.ErrFileTooShort),
                         (wrapped.Length - 1, AbstractHkdfGuardKmsLibrary.ErrFileTooShort),
                         (wrapped.Length + 1, AbstractHkdfGuardKmsLibrary.ErrFileTooLong),
                         (4096, AbstractHkdfGuardKmsLibrary.ErrFileTooLong),
                     })
            {
                var contents = new byte[size];
                wrapped.AsSpan(0, Math.Min(size, wrapped.Length)).CopyTo(contents);
                await RefusedAsync<InvalidDataException>(await WriteAsync(directory, $"size-{size}.bin", contents), status);
            }
        });

    public static TheoryData<string> PlaintextKeyForms => new() { "raw", "hex", "lower-hex", "base64", "base64-with-newline" };

    [LinuxNativeIntegrationTheory(NeedsKeyFileDirectory = true)]
    [MemberData(nameof(PlaintextKeyForms))]
    public async Task AFileHoldingWhatLooksLikeAnUnwrappedDek_IsRefusedAsAKeyExposure(string form)
    {
        var dek = RandomNumberGenerator.GetBytes(DekLength);
        var contents = form switch
        {
            "raw" => dek,
            "hex" => System.Text.Encoding.ASCII.GetBytes(Convert.ToHexString(dek)),
            "lower-hex" => System.Text.Encoding.ASCII.GetBytes(Convert.ToHexStringLower(dek)),
            "base64" => System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(dek)),
            _ => System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(dek) + "\n"),
        };

        await WithKeyFileFolderAsync(async (directory, _) =>
            await RefusedAsync<InvalidDataException>(await WriteAsync(directory, $"plaintext-{form}.bin", contents), AbstractHkdfGuardKmsLibrary.ErrFilePlaintextKey));
    }

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public Task AChangeToThePayloadsStructure_IsRefusedWhenRead_ButAChangedTagOnlyAtUnwrap()
        => WithKeyFileFolderAsync(async (directory, wrapped) =>
        {
            // The version byte and a byte mid-payload are checked when the file is read; the AEAD
            // tag can only be checked with the KEK, so a changed tag reads fine and fails unwrap.
            foreach (var position in new[] { 0, wrapped.Length / 2 })
            {
                var tampered = (byte[])wrapped.Clone();
                tampered[position] ^= 0x01;
                await RefusedAsync<InvalidDataException>(await WriteAsync(directory, $"structure-{position}.bin", tampered), AbstractHkdfGuardKmsLibrary.ErrFileMalformed);
            }

            var tag = (byte[])wrapped.Clone();
            tag[^1] ^= 0x01;
            var read = await Reader.ReadKeyFileAsync(await WriteAsync(directory, "tag.bin", tag));
            var destination = new byte[DekLength];
            await Assert.ThrowsAsync<CryptographicException>(async () => await new NativeHkdfKeyWrapperV1(Service).UnwrapAsync(read, destination));
            Assert.All(destination, b => Assert.Equal(0, b));
        });

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public Task AMissingFileOrFolder_IsNotFound_AndAFolderIsNotAKeyFile()
        => WithKeyFileFolderAsync(async (directory, _) =>
        {
            await RefusedAsync<FileNotFoundException>(Path.Combine(directory, "missing.bin"), AbstractHkdfGuardKmsLibrary.ErrFileNotFound);
            await RefusedAsync<FileNotFoundException>(Path.Combine(directory, "missing", "key.bin"), AbstractHkdfGuardKmsLibrary.ErrFileNotFound);
            var thrown = await Assert.ThrowsAsync<IOException>(async () => await Reader.ReadKeyFileAsync(directory));
            Assert.Contains($"status {AbstractHkdfGuardKmsLibrary.ErrFileIo} (", thrown.Message);
        });

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public Task ALink_IsFollowed_OnlyWhereItLeadsIsTrustedToo()
        => WithKeyFileFolderAsync(async (directory, wrapped) =>
        {
            // The library judges where a link leads, not the link: within private folders it is
            // followed; into /tmp (sticky, world-writable) it is refused, as is /tmp itself.
            var key = await WriteAsync(directory, "key.bin", wrapped);
            var fileLink = Path.Combine(directory, "file-link.bin");
            File.CreateSymbolicLink(fileLink, key);
            var folderLink = Path.Combine(directory, "folder-link");
            Directory.CreateSymbolicLink(folderLink, directory);

            Assert.Equal(wrapped, await Reader.ReadKeyFileAsync(fileLink));
            Assert.Equal(wrapped, await Reader.ReadKeyFileAsync(Path.Combine(folderLink, "key.bin")));

            var shared = Directory.CreateTempSubdirectory("hkdfguard-shared-");
            try
            {
                Assert.StartsWith("/tmp/", shared.FullName + "/");
                var exposed = await WriteAsync(shared.FullName, "key.bin", wrapped);
                var intoShared = Path.Combine(directory, "into-tmp.bin");
                File.CreateSymbolicLink(intoShared, exposed);
                var sharedFolderLink = Path.Combine(directory, "tmp-folder");
                Directory.CreateSymbolicLink(sharedFolderLink, shared.FullName);

                await RefusedAsync<UnauthorizedAccessException>(exposed, AbstractHkdfGuardKmsLibrary.ErrFileUntrusted);
                await RefusedAsync<UnauthorizedAccessException>(intoShared, AbstractHkdfGuardKmsLibrary.ErrFileUntrusted);
                await RefusedAsync<UnauthorizedAccessException>(Path.Combine(sharedFolderLink, "key.bin"), AbstractHkdfGuardKmsLibrary.ErrFileUntrusted);
            }
            finally
            {
                shared.Delete(recursive: true);
            }
        });

    [LinuxNativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task AKeyFileAnotherAccountCouldRewrite_IsRefused_WhileOwnerOnlyAndGroupReadAreNot()
    {
        // A group- or other-writable key file could be replaced by another account, so the library
        // refuses it (-39) whatever the folders above it. Group read is fine: hkdfguard wrap
        // --group hands a key file to a service's group as 0640. This is also why tests write key
        // files 0600 explicitly: an Ubuntu desktop session's umask of 002 makes .NET write 0664.
        var directory = TestDirectories.CreateKeyFileDirectory("hkdfguard-mode-");
        try
        {
            var path = Path.Combine(directory, "key.bin");
            await TestDirectories.WriteKeyFileAsync(path, Wrap(RandomNumberGenerator.GetBytes(DekLength)));
            var reader = new NativeHkdfKeyWrapperV1(Service);

            foreach (var mode in new[] { UnixFileMode.GroupWrite, UnixFileMode.OtherWrite })
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead | mode);

                var refused = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () => await reader.ReadKeyFileAsync(path));
                Assert.Contains($"status {AbstractHkdfGuardKmsLibrary.ErrFileUntrusted}", refused.Message);
            }

            foreach (var readable in new[] { UnixFileMode.None, UnixFileMode.GroupRead, UnixFileMode.GroupRead | UnixFileMode.OtherRead })
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | readable);
                Assert.NotEmpty(await reader.ReadKeyFileAsync(path));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [LinuxNativeIntegrationFact(NeedsCli = true, NeedsKeyFileDirectory = true)]
    public async Task AKeyFileWrappedByTheProvisioningTool_RevealsItsDekThroughTheWrapper()
    {
        // The deployment path: hkdfguard wraps a delivered DEK on the host, in its own process,
        // and the application reads the key file through the native library (which refuses one
        // below a group- or other-writable directory, so this is a private folder, not /tmp) and
        // unwraps it through this binding.
        var directory = TestDirectories.CreateKeyFileDirectory("hkdfguard-cli-");
        try
        {
            var dek = RandomNumberGenerator.GetBytes(DekLength);
            var dekFile = Path.Combine(directory, "dek");
            var keyFile = Path.Combine(directory, "key.bin");
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
            Assert.True(exitCode == 0, $"hkdfguard wrap exited {exitCode}: {output}");
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(keyFile));

            var wrapper = new NativeHkdfKeyWrapperV1(Service);
            var recovered = new byte[DekLength];
            var written = await wrapper.UnwrapAsync(await wrapper.ReadKeyFileAsync(keyFile), recovered);

            Assert.Equal(DekLength, written);
            Assert.Equal(dek, recovered);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [LinuxNativeIntegrationFact(NeedsCli = true)]
    public async Task TheProvisioningTool_ReportsTheTestServiceAsProvisioned()
    {
        var (exitCode, output) = await RunCliAsync("provision", "--service-name", Service);

        Assert.True(exitCode == 0, $"hkdfguard provision exited {exitCode}: {output}");
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
