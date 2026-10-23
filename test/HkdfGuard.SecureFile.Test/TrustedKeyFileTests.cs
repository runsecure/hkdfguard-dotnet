using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using HkdfGuard.Abstractions;
using HkdfGuard.SecureFile;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.SecureFile.Test;

public class TrustedKeyFileTests
{
    // About the size of a KMS ciphertext blob for a 32-byte DEK.
    private static byte[] Wrapped() => RandomNumberGenerator.GetBytes(184);

    private static ValueTask<byte[]> ReadContents(byte[] contents)
        => TrustedKeyFile.ReadContentsAsync(new MemoryStream(contents), "v1.key", CancellationToken.None);

    [Fact]
    public async Task ReadContents_AWrappedKey_IsReturnedExactly()
    {
        var wrapped = Wrapped();

        Assert.Equal(wrapped, await ReadContents(wrapped));
    }

    [Fact]
    public async Task ReadContents_ExactlyTheLimit_IsAccepted()
    {
        var wrapped = RandomNumberGenerator.GetBytes(WrappedKeyLimits.MaxBytes);

        Assert.Equal(wrapped, await ReadContents(wrapped));
    }

    [Fact]
    public async Task ReadContents_Empty_IsRefused()
    {
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () => await ReadContents([]));
        Assert.Contains("empty", ex.Message);
    }

    [Fact]
    public async Task ReadContents_OverTheLimit_IsRefused_ReadingOnlyOneBytePast()
    {
        var stream = new MemoryStream(new byte[WrappedKeyLimits.MaxBytes * 4]);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await TrustedKeyFile.ReadContentsAsync(stream, "v1.key", CancellationToken.None));
        Assert.Equal(WrappedKeyLimits.MaxBytes + 1, stream.Position);
    }

    [Fact]
    public async Task ReadContents_APlaintextKey_IsRefused_AsExposed()
    {
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () => await ReadContents(RandomNumberGenerator.GetBytes(32)));
        Assert.Contains("exposed", ex.Message);
    }

    [Fact]
    public async Task ReadContents_HonorsCancellation()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await TrustedKeyFile.ReadContentsAsync(new MemoryStream(Wrapped()), "v1.key", new CancellationToken(canceled: true)));
    }

    public static TheoryData<string> PlaintextKeysAsText()
    {
        // Fixed, so the standard and URL-safe encodings always differ: FB EF BE encodes as "++++",
        // FF FF FF as "////". A random key would sometimes encode with neither, merging two rows.
        var key = Enumerable.Range(0, 32).Select(i => (i % 6) switch { 0 => (byte)0xFB, 1 => (byte)0xEF, 2 => (byte)0xBE, _ => (byte)0xFF }).ToArray();
        var base64 = Convert.ToBase64String(key);
        var urlSafe = base64.Replace('+', '-').Replace('/', '_');
        return new TheoryData<string>
        {
            Convert.ToHexString(key),
            Convert.ToHexString(key).ToLowerInvariant() + "\n",
            base64,
            base64.TrimEnd('='),
            urlSafe,
            urlSafe.TrimEnd('=') + "\r\n",
            "  \t" + base64 + " \n",
        };
    }

    [Theory]
    [MemberData(nameof(PlaintextKeysAsText))]
    public void LooksLikePlaintextKey_AKeyWrittenAsText_IsDetected(string text)
        => Assert.True(TrustedKeyFile.LooksLikePlaintextKey(Encoding.ASCII.GetBytes(text)));

    [Fact]
    public void LooksLikePlaintextKey_RawKey_IsDetected()
        => Assert.True(TrustedKeyFile.LooksLikePlaintextKey(RandomNumberGenerator.GetBytes(32)));

    public static TheoryData<string> NotPlaintextKeys() => new()
    {
        new string('a', 63),                                   // one hex digit short
        new string('a', 62) + "zz",                            // not hex
        new string('A', 42),                                   // too short for base64
        new string('A', 45),                                   // too long for base64
        new string('A', 41) + "+-",                            // mixes the two alphabets
        new string('A', 42) + "!",                             // not base64
        new string('A', 43) + "==",                            // 45 characters
        new string('A', 42) + "==",                            // 44, but padded for 31 bytes
    };

    [Theory]
    [MemberData(nameof(NotPlaintextKeys))]
    public void LooksLikePlaintextKey_OtherText_IsNotDetected(string text)
        => Assert.False(TrustedKeyFile.LooksLikePlaintextKey(Encoding.ASCII.GetBytes(text)));

    [Fact]
    public void LooksLikePlaintextKey_AWrappedKey_IsNotDetected()
    {
        Assert.False(TrustedKeyFile.LooksLikePlaintextKey(Wrapped()));
        Assert.False(TrustedKeyFile.LooksLikePlaintextKey(RandomNumberGenerator.GetBytes(TrustedKeyFile.PlaintextTextScanLimit)));
    }

    [Fact]
    public async Task ReadAsync_EmptyPath_IsAnArgumentError()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(async () => await TrustedKeyFile.ReadAsync("", KeyFileTrust.AdministratorsOnly, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AFileInTheUsersOwnFolder_IsRefusedByDefault()
    {
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("v1.key", Wrapped());

        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await TrustedKeyFile.ReadAsync(path, KeyFileTrust.AdministratorsOnly, CancellationToken.None));
        Assert.Contains("not trusted", ex.Message);
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_WithTheUserTrusted_ReadsTheFile()
    {
        using var dir = new WindowsTempDirectory();
        var wrapped = Wrapped();
        var path = dir.Write("v1.key", wrapped);

        Assert.Equal(wrapped, await TrustedKeyFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_ARelativePath_IsReadFromTheWorkingDirectory()
    {
        using var dir = new WindowsTempDirectory();
        var wrapped = Wrapped();
        var path = dir.Write("v1.key", wrapped);

        var relative = Path.GetRelativePath(Environment.CurrentDirectory, path);
        Assert.Equal(wrapped, await TrustedKeyFile.ReadAsync(relative, WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AFileOthersMayWrite_IsRefused_EvenWithTheUserTrusted()
    {
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("v1.key", Wrapped());
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), System.Security.AccessControl.FileSystemRights.Write,
            System.Security.AccessControl.AccessControlType.Allow));
        file.SetAccessControl(security);

        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await TrustedKeyFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
        Assert.Contains("grants", ex.Message);
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AShortName_IsExpanded_AndTheRealPathChecked()
    {
        using var dir = new WindowsTempDirectory();
        var wrapped = Wrapped();
        var path = dir.Write("a-long-key-file-name.key", wrapped);
        var shortPath = WindowsTempDirectory.ShortPath(path);

        // Path.GetFullPath expands 8.3 names, so the folders checked are the real ones.
        Assert.Equal(wrapped, await TrustedKeyFile.ReadAsync(shortPath, WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await TrustedKeyFile.ReadAsync(shortPath, KeyFileTrust.AdministratorsOnly, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AMissingFile_IsNotFound()
    {
        using var dir = new WindowsTempDirectory();

        await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await TrustedKeyFile.ReadAsync(Path.Combine(dir.Path, "missing.key"), WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AFileOpenForWriting_IsRefused()
    {
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("v1.key", Wrapped());
        await using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);

        await Assert.ThrowsAsync<IOException>(async () =>
            await TrustedKeyFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, CancellationToken.None));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AUncPath_IsRefusedWithoutBeingOpened()
    {
        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await TrustedKeyFile.ReadAsync(@"\\hkdfguard-no-such-server.invalid\share\v1.key", KeyFileTrust.AdministratorsOnly, CancellationToken.None));
        Assert.Contains("UNC", ex.Message);
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_AFileUnderTheSharedTempDirectory_IsRefused()
    {
        // /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
        var dir = Directory.CreateDirectory(Path.Combine("/tmp", $"hkdfguard-{Guid.NewGuid():N}"));
        try
        {
            var path = Path.Combine(dir.FullName, "v1.key");
            await File.WriteAllBytesAsync(path, Wrapped());

            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await TrustedKeyFile.ReadAsync(path, UnixTrustCurrentUser(), CancellationToken.None));
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_AFileTheUserOwns_IsRefusedByDefault()
    {
        if (UnixTrustCurrentUser().UnixUserIds[0] == 0)
            return; // running as root, whose files are trusted

        var dir = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, $"keys-{Guid.NewGuid():N}"));
        try
        {
            var path = Path.Combine(dir.FullName, "v1.key");
            await File.WriteAllBytesAsync(path, Wrapped());

            await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await TrustedKeyFile.ReadAsync(path, KeyFileTrust.AdministratorsOnly, CancellationToken.None));
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_AMissingFile_IsNotFound()
    {
        await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await TrustedKeyFile.ReadAsync($"/hkdfguard-missing-{Guid.NewGuid():N}.key", KeyFileTrust.AdministratorsOnly, CancellationToken.None));
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_ARootOwnedSystemFile_PassesTheLocationChecks()
    {
        // /etc/hosts: root-owned all the way up, and not a key - so it's refused for its
        // contents (or size), never for where it lives.
        var ex = await Record.ExceptionAsync(async () => await TrustedKeyFile.ReadAsync("/etc/hosts", KeyFileTrust.AdministratorsOnly, CancellationToken.None));

        Assert.IsNotType<UnauthorizedAccessException>(ex);
    }

    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    private static KeyFileTrust UnixTrustCurrentUser()
    {
        var probe = Path.Combine(AppContext.BaseDirectory, "hkdfguard.trust.probe");
        File.WriteAllBytes(probe, []);
        try
        {
            // The probe was just created by this process, so its owner and group are this
            // process's effective user and group.
            var status = UnixNative.GetStatusOrNull(probe)!.Value;
            return new KeyFileTrust { UnixUserIds = [status.OwnerId], UnixGroupIds = [status.GroupId] };
        }
        finally
        {
            File.Delete(probe);
        }
    }
}
