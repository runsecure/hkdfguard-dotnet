using System.Runtime.Versioning;
using System.Security.Cryptography;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.SecureFile.Test;

public class TrustedFileTests
{
    private const int Limit = 64;

    private static ValueTask<byte[]> ReadContents(Stream stream, int maxBytes = Limit)
        => TrustedFile.ReadContentsAsync(stream, "secret.enc", maxBytes, CancellationToken.None);

    private static ValueTask<int> ReadContentsLength(Stream stream, int maxBytes = Limit)
        => TrustedFile.ReadContentsAsync(stream, "secret.enc", maxBytes, contents => contents.Length, CancellationToken.None);

    [Fact]
    public async Task ReadContents_ReturnsTheContentsExactly()
    {
        var contents = RandomNumberGenerator.GetBytes(40);

        Assert.Equal(contents, await ReadContents(new MemoryStream(contents)));
    }

    [Fact]
    public async Task ReadContents_ExactlyTheLimit_IsAccepted()
    {
        var contents = RandomNumberGenerator.GetBytes(Limit);

        Assert.Equal(contents, await ReadContents(new MemoryStream(contents)));
        Assert.Equal(Limit, await ReadContentsLength(new MemoryStream(contents)));
    }

    [Fact]
    public async Task ReadContents_AnEmptyFile_IsReturnedEmpty()
    {
        Assert.Empty(await ReadContents(new MemoryStream()));
        Assert.Equal(0, await ReadContentsLength(new MemoryStream()));
    }

    [Fact]
    public async Task ReadContents_OverTheLimit_IsRefused_ReadingOnlyOneBytePast()
    {
        var stream = new MemoryStream(new byte[Limit * 4]);
        var ex = await Assert.ThrowsAsync<InvalidDataException>(async () => await ReadContents(stream));
        Assert.Contains($"larger than {Limit} bytes", ex.Message);
        Assert.Equal(Limit + 1, stream.Position);

        var parsed = false;
        stream = new MemoryStream(new byte[Limit * 4]);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await TrustedFile.ReadContentsAsync(stream, "secret.enc", Limit, _ => parsed = true, CancellationToken.None));
        Assert.False(parsed);
        Assert.Equal(Limit + 1, stream.Position);
    }

    [Fact]
    public async Task ReadContents_AppliesNoKeyFileRules()
    {
        // TrustedKeyFile refuses exactly 32 bytes as a probable plaintext key; TrustedFile leaves
        // the contents to its caller.
        var contents = RandomNumberGenerator.GetBytes(32);

        Assert.Equal(contents, await ReadContents(new MemoryStream(contents)));
    }

    [Fact]
    public async Task ReadContents_ParserSeesTheContents_AndItsResultIsReturned()
    {
        var contents = RandomNumberGenerator.GetBytes(40);

        Assert.Equal(contents, await TrustedFile.ReadContentsAsync(new MemoryStream(contents), "secret.enc", Limit,
            span => span.ToArray(), CancellationToken.None));
    }

    [Fact]
    public async Task ReadContents_AParserException_Propagates()
    {
        await Assert.ThrowsAsync<FormatException>(async () =>
            await TrustedFile.ReadContentsAsync<int>(new MemoryStream([1, 2, 3]), "secret.enc", Limit,
                _ => throw new FormatException(), CancellationToken.None));
    }

    [Fact]
    public async Task ReadContents_HonorsCancellation()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await TrustedFile.ReadContentsAsync(new MemoryStream([1, 2, 3]), "secret.enc", Limit, new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task ReadAsync_InvalidArguments_AreRefusedBeforeAnythingIsOpened()
    {
        var trust = KeyFileTrust.AdministratorsOnly;

        await Assert.ThrowsAsync<ArgumentException>(async () => await TrustedFile.ReadAsync("", trust, Limit));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await TrustedFile.ReadAsync(null!, trust, Limit));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await TrustedFile.ReadAsync("secret.enc", null!, Limit));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await TrustedFile.ReadAsync("secret.enc", trust, 0));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await TrustedFile.ReadAsync("secret.enc", trust, Array.MaxLength));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await TrustedFile.ReadAsync<int>("secret.enc", trust, Limit, null!));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await TrustedFile.ReadAsync("secret.enc", trust, -1, span => span.Length));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AFileInTheUsersOwnFolder_IsRefusedByDefault()
    {
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("secret.enc", RandomNumberGenerator.GetBytes(40));

        var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await TrustedFile.ReadAsync(path, KeyFileTrust.AdministratorsOnly, Limit));
        Assert.Contains("not trusted", ex.Message);
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_WithTheUserTrusted_ReadsTheFileThroughEitherOverload()
    {
        using var dir = new WindowsTempDirectory();
        var contents = RandomNumberGenerator.GetBytes(40);
        var path = dir.Write("secret.enc", contents);

        Assert.Equal(contents, await TrustedFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, Limit));
        Assert.Equal(contents, await TrustedFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, Limit, span => span.ToArray()));
    }

    [WindowsFact]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_Windows_AFileOverTheLimit_IsRefused()
    {
        using var dir = new WindowsTempDirectory();
        var path = dir.Write("secret.enc", new byte[Limit + 1]);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await TrustedFile.ReadAsync(path, WindowsTempDirectory.TrustCurrentUser, Limit));
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_ARootOwnedSystemFile_IsReadThroughEitherOverload()
    {
        // /etc/hosts: root-owned all the way up (through macOS's root-owned /etc link), and any
        // contents at all are accepted.
        var expected = await File.ReadAllBytesAsync("/etc/hosts");

        Assert.Equal(expected, await TrustedFile.ReadAsync("/etc/hosts", KeyFileTrust.AdministratorsOnly, 1024 * 1024));
        Assert.Equal(expected.Length, await TrustedFile.ReadAsync("/etc/hosts", KeyFileTrust.AdministratorsOnly, 1024 * 1024, span => span.Length));
    }

    [UnixFact]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    public async Task ReadAsync_Unix_AFileUnderTheSharedTempDirectory_IsRefused()
    {
        var dir = Directory.CreateDirectory(Path.Combine("/tmp", $"hkdfguard-{Guid.NewGuid():N}"));
        try
        {
            var path = Path.Combine(dir.FullName, "secret.enc");
            await File.WriteAllBytesAsync(path, RandomNumberGenerator.GetBytes(40));

            var ex = await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
                await TrustedFile.ReadAsync(path, KeyFileTrust.AdministratorsOnly, Limit));
            Assert.Contains("not trusted", ex.Message);
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
            await TrustedFile.ReadAsync($"/hkdfguard-missing-{Guid.NewGuid():N}.enc", KeyFileTrust.AdministratorsOnly, Limit));
    }
}
