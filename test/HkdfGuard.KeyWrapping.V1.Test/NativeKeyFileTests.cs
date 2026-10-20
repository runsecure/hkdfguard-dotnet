using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Reading key files through the real native library's hkdfguard_open_file. Refusals of a file's
/// size, contents or location need no KEK, so they run wherever the Windows library is installed;
/// reading back a real wrapped key needs a provisioned service (see NativeTestEnvironment). Key files
/// are written to TestDirectories.CreateKeyFileDirectory: on Linux the library refuses any key file
/// below a group- or other-writable directory, so never under /tmp.
/// </summary>
public sealed class NativeKeyFileTests : IDisposable
{
    // Created on first use, as a folder the native library trusts for key files: in its long form
    // on Windows, and on Linux a private one outside /tmp (tests that use it there are gated with
    // NeedsKeyFileDirectory).
    private string? _created;

    private string KeyFileDirectory => _created ??= TestDirectories.CreateKeyFileDirectory("hkdfguard-keyfile-");

    public void Dispose()
    {
        if (_created is not null)
            Directory.Delete(_created, recursive: true);
    }

    private static string Service => NativeTestEnvironment.ProvisionedService;

    // Any valid name: reading a file never touches a KEK.
    private static NativeHkdfKeyWrapperV1 Reader => new("hkdfguard.keyfile.reader");

    private string Write(string name, byte[] contents)
    {
        var path = Path.Combine(KeyFileDirectory, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    private async Task<(string Path, byte[] Wrapped, byte[] Dek)> WrapToFileAsync()
    {
        var dek = RandomNumberGenerator.GetBytes(AbstractHkdfGuardKmsLibrary.DekLength);
        var buffer = new byte[WrappedKeyLimits.MaxBytes];
        var length = await new NativeHkdfKeyWrapperV1(Service).WrapAsync(dek, buffer);
        var wrapped = buffer[..length];
        return (Write("wrapped-dek.bin", wrapped), wrapped, dek);
    }

    // --- The key file folder -------------------------------------------------------------------

    [WindowsFact]
    public void TheKeyFileFolder_IsInItsLongForm()
    {
        // hkdfguard_open_file refuses an 8.3 short name anywhere in a path, so every test here
        // relies on TestDirectories expanding one (C:\Users\RUNNER~1\... on GitHub-hosted runners).
        foreach (var part in KeyFileDirectory.Split(Path.DirectorySeparatorChar))
        {
            var tilde = part.IndexOf('~');
            Assert.False(tilde >= 0 && tilde + 1 < part.Length && char.IsAsciiDigit(part[tilde + 1]), $"{KeyFileDirectory} still has the short name '{part}'.");
        }
    }

    // --- A real key file ------------------------------------------------------------------------

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task AKeyFileTheWrapperWrote_ReadsBackStillWrapped_AndUnwrapsToItsDek()
    {
        var (path, wrapped, dek) = await WrapToFileAsync();
        var wrapper = new NativeHkdfKeyWrapperV1(Service);

        var read = await wrapper.ReadKeyFileAsync(path);

        Assert.Equal(wrapped, read);
        var recovered = new byte[dek.Length];
        Assert.Equal(dek.Length, await wrapper.UnwrapAsync(read, recovered));
        Assert.Equal(dek, recovered);
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task AKeyRing_BuiltFromAKeyFile_ReadsItThroughTheNativeLibrary()
    {
        var (path, _, _) = await WrapToFileAsync();

        await using var ring = await new KeyRingBuilder()
            .WithKeyWrapper(new NativeHkdfKeyWrapperV1(Service))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithKeyRefreshInterval(60)
            .WithKeyFile(4, path)
            .BuildAsync();

        Assert.Equal(4, ring.CurrentVersion);
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task AKeyFileOfTheRightSizeWithAnUnknownVersion_IsMalformed()
    {
        var (path, wrapped, _) = await WrapToFileAsync();
        // The version byte: first on Linux and Windows; on macOS the suite id, after the 32-byte
        // KEK fingerprint (which hkdfguard_open_file doesn't check - unwrap does).
        wrapped[OperatingSystem.IsMacOS() ? 32 : 0] ^= 0xFF;
        await File.WriteAllBytesAsync(path, wrapped);

        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await Reader.ReadKeyFileAsync(path));

        Assert.Contains("status -38", thrown.Message);
    }

    // --- Files the native library refuses, whatever the KEK --------------------------------------

    [InstalledNativeLibraryFact(NeedsKeyFileDirectory = true)]
    public void TheInstalledLibrary_AnswersOpenFile_WithADescribedRefusal()
    {
        // hkdfguard_open_file needs no KEK, on any platform: a file that isn't there is refused
        // with a status this platform describes - which proves the binding reached it. A library
        // that can't be loaded or fails verification throws something else, and fails this test.
        var path = Path.Combine(KeyFileDirectory, "missing", "dek.bin");

        var thrown = Record.Exception(() => NativeHost.Library.OpenFile(path));

        Assert.True(thrown is IOException or UnauthorizedAccessException or ArgumentException, $"OpenFile threw {thrown?.GetType().Name ?? "nothing"}: {thrown?.Message}");
        Assert.DoesNotContain("unknown status", thrown!.Message);
    }

    [InstalledWindowsLibraryFact]
    public async Task AMissingFile_IsNotFound()
    {
        var path = Path.Combine(KeyFileDirectory, "missing.bin");

        var thrown = await Assert.ThrowsAsync<FileNotFoundException>(async () => await Reader.ReadKeyFileAsync(path));

        Assert.Equal(path, thrown.FileName);
    }

    [InstalledWindowsLibraryFact]
    public async Task AFileInAMissingFolder_IsNotFound()
        => await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await Reader.ReadKeyFileAsync(Path.Combine(KeyFileDirectory, "no-such-folder", "dek.bin")));

    public static TheoryData<string, byte[]> PlaintextKeys
    {
        get
        {
            var dek = RandomNumberGenerator.GetBytes(32);
            return new()
            {
                { "raw", dek },
                { "hex", Encoding.ASCII.GetBytes(Convert.ToHexString(dek)) },
                { "lower-hex", Encoding.ASCII.GetBytes(Convert.ToHexString(dek).ToLowerInvariant()) },
                { "base64", Encoding.ASCII.GetBytes(Convert.ToBase64String(dek)) },
                { "base64-with-newline", Encoding.ASCII.GetBytes(Convert.ToBase64String(dek) + "\n") },
            };
        }
    }

    [InstalledWindowsLibraryTheory]
    [MemberData(nameof(PlaintextKeys))]
    public async Task AFileHoldingWhatLooksLikeAnUnwrappedKey_IsRefusedAsAKeyExposure(string form, byte[] contents)
    {
        var path = Write($"plaintext-{form}.bin", contents);

        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await Reader.ReadKeyFileAsync(path));

        Assert.Contains("status -37", thrown.Message);
        Assert.Contains("key exposure", thrown.Message);
    }

    [InstalledWindowsLibraryTheory]
    [InlineData(0, -35)]
    [InlineData(100, -35)]
    [InlineData(131, -35)]
    [InlineData(133, -36)]
    [InlineData(4096, -36)]
    public async Task AFileOfTheWrongSize_IsRefused(int size, int status)
    {
        var contents = new byte[size];
        if (size > 0)
            contents[0] = 0x7F; // never mistaken for text
        var path = Write($"size-{size}.bin", contents);

        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await Reader.ReadKeyFileAsync(path));

        Assert.Contains($"status {status}", thrown.Message);
    }

    [InstalledWindowsLibraryFact]
    public async Task AFolder_IsNotAKeyFile()
        => await Assert.ThrowsAnyAsync<IOException>(async () => await Reader.ReadKeyFileAsync(KeyFileDirectory));

    [InstalledWindowsLibraryFact]
    public async Task AFileReachedThroughAJunction_IsUntrusted()
    {
        var target = Directory.CreateDirectory(Path.Combine(KeyFileDirectory, "real")).FullName;
        File.WriteAllBytes(Path.Combine(target, "dek.bin"), new byte[132]);
        var junction = Path.Combine(KeyFileDirectory, "junction");

        // mklink /J needs no elevation, unlike a symbolic link.
        using (var mklink = Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "mklink", "/J", junction, target])
               { RedirectStandardOutput = true, RedirectStandardError = true })!)
        {
            await mklink.WaitForExitAsync();
            Assert.True(mklink.ExitCode == 0, await mklink.StandardError.ReadToEndAsync());
        }

        try
        {
            var thrown = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await Reader.ReadKeyFileAsync(Path.Combine(junction, "dek.bin")));

            Assert.Contains("status -39", thrown.Message);
        }
        finally
        {
            Directory.Delete(junction); // removes the junction itself, not what it points at
        }
    }

    [InstalledWindowsLibraryFact]
    public async Task AKeyRing_RefusesToBuildFromAPlaintextKeyFile()
    {
        var path = Write("plaintext.bin", RandomNumberGenerator.GetBytes(32));

        await Assert.ThrowsAsync<InvalidDataException>(() => new KeyRingBuilder()
            .WithKeyWrapper(Reader)
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithKeyRefreshInterval(60)
            .WithKeyFile(1, path)
            .BuildAsync());
    }
}
