using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class KmsLibraryContractTests
{
    [Fact]
    public void AbstractHkdfGuardKmsLibrary_Constants_MatchExpected()
    {
        Assert.Equal(32, AbstractHkdfGuardKmsLibrary.DekLength);
        Assert.Equal(0, AbstractHkdfGuardKmsLibrary.Ok);
    }

    /// <summary>Every status code, exactly as every platform's hkdfguard.h defines it.</summary>
    public static TheoryData<int, int> SharedStatusCodes => new()
    {
        { AbstractHkdfGuardKmsLibrary.ErrInvalidArgument, -1 },
        { AbstractHkdfGuardKmsLibrary.ErrBufferTooSmall, -2 },
        { AbstractHkdfGuardKmsLibrary.ErrProviderUnavailable, -3 },
        { AbstractHkdfGuardKmsLibrary.ErrProviderError, -4 },
        { AbstractHkdfGuardKmsLibrary.ErrCryptoError, -5 },
        { AbstractHkdfGuardKmsLibrary.ErrInternalError, -6 },
        { AbstractHkdfGuardKmsLibrary.ErrInvalidServiceName, -8 },
        { AbstractHkdfGuardKmsLibrary.ErrPolicyInvalid, -9 },
        { AbstractHkdfGuardKmsLibrary.ErrPayloadMalformed, -10 },
        { AbstractHkdfGuardKmsLibrary.ErrPayloadAuthFailed, -11 },
        { AbstractHkdfGuardKmsLibrary.ErrPayloadUnsupported, -12 },
        { AbstractHkdfGuardKmsLibrary.ErrKekFingerprintMismatch, -16 },
        { AbstractHkdfGuardKmsLibrary.ErrKekNotFound, -17 },
        { AbstractHkdfGuardKmsLibrary.ErrKekAccessDenied, -18 },
        { AbstractHkdfGuardKmsLibrary.ErrKekInvalid, -19 },
        { AbstractHkdfGuardKmsLibrary.ErrProcessHardeningFailed, -20 },
        { AbstractHkdfGuardKmsLibrary.ErrFileNotFound, -32 },
        { AbstractHkdfGuardKmsLibrary.ErrFileAccessDenied, -33 },
        { AbstractHkdfGuardKmsLibrary.ErrFileIo, -34 },
        { AbstractHkdfGuardKmsLibrary.ErrFileTooShort, -35 },
        { AbstractHkdfGuardKmsLibrary.ErrFileTooLong, -36 },
        { AbstractHkdfGuardKmsLibrary.ErrFilePlaintextKey, -37 },
        { AbstractHkdfGuardKmsLibrary.ErrFileMalformed, -38 },
        { AbstractHkdfGuardKmsLibrary.ErrFileUntrusted, -39 },
        { AbstractHkdfGuardKmsLibrary.ErrWinGroupInvalid, -64 },
        { AbstractHkdfGuardKmsLibrary.ErrMacAccessControlCreationFailed, -96 },
        { AbstractHkdfGuardKmsLibrary.ErrMacKeyGenerationFailed, -97 },
        { AbstractHkdfGuardKmsLibrary.ErrMacKeychainWriteFailed, -98 },
        { AbstractHkdfGuardKmsLibrary.ErrMacKekVerificationFailed, -99 },
        { AbstractHkdfGuardKmsLibrary.ErrMacKeychainReadFailed, -100 },
    };

    [Theory]
    [MemberData(nameof(SharedStatusCodes))]
    public void TheStatusCodes_MatchTheNativeHeader(int constant, int expected)
        => Assert.Equal(expected, constant);

    public static TheoryData<string> Platforms => new() { "Windows", "Linux", "macOS" };

    private static AbstractHkdfGuardKmsLibrary LibraryFor(string platform) => platform switch
    {
        "Windows" => new WindowsHkdfGuardKmsLibrary(),
        "Linux" => new LinuxHkdfGuardKmsLibrary(),
        _ => new MacOsHkdfGuardKmsLibrary(),
    };

    [Theory]
    [MemberData(nameof(Platforms))]
    public void EveryPlatform_DescribesEveryDefinedStatus_AndNothingElse(string platform)
    {
        var library = LibraryFor(platform);

        foreach (var row in SharedStatusCodes)
            Assert.False(string.IsNullOrEmpty(library.DescribeStatus((int)row[0])), $"{platform}: no description for {row[0]}");

        // Reserved and unassigned codes, and anything positive, have no meaning to describe.
        foreach (var unassigned in new[] { -7, -13, -15, -21, -31, -40, -63, -65, -80, -95, -101, 1 })
            Assert.Null(library.DescribeStatus(unassigned));
    }

    [Theory]
    [MemberData(nameof(Platforms))]
    public void EveryPlatform_SaysHowToProvisionAMissingKek(string platform)
        => Assert.Contains("provision", LibraryFor(platform).DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrKekNotFound));

    [Fact]
    public void Windows_SaysWhichGroupGrantsAccessToAKek()
    {
        var description = new WindowsHkdfGuardKmsLibrary().DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrKekAccessDenied);

        Assert.Contains("not authorized", description);
        Assert.Contains("HkdfGuardUsers", description);
    }

    [Fact]
    public void Windows_NamesTheCurrentCommandLineTool()
    {
        var description = new WindowsHkdfGuardKmsLibrary().DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrKekNotFound);

        Assert.Contains("hkdfguard provision", description);
        Assert.DoesNotContain("v1-initialize", description);
    }

    [Fact]
    public void Linux_DescribesAFingerprintMismatchAsADifferentKek()
        => Assert.Contains("different KEK", new LinuxHkdfGuardKmsLibrary().DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrKekFingerprintMismatch));

    [Fact]
    public void APlaintextKeyFile_IsDescribedAsAKeyExposure()
        => Assert.Contains("key exposure", new FakeHkdfGuardKmsLibrary().DescribeStatus(AbstractHkdfGuardKmsLibrary.ErrFilePlaintextKey));

    [Fact]
    public void EachPlatformsLibrary_IsRoutedUnderItsOwnName()
    {
        Assert.Equal("HkdfGuard.Kms.Windows.v1", WindowsHkdfGuardKmsLibrary.LibraryName);
        Assert.Equal("HkdfGuard.Kms.Linux.v1", LinuxHkdfGuardKmsLibrary.LibraryName);
        Assert.Equal("hkdfguard_v1", MacOsHkdfGuardKmsLibrary.LibraryName);
    }

    // --- OpenFile: the interop returns the file's bytes, or throws ------------------------------

    [Fact]
    public void OpenFile_ReturnsExactlyTheBytesTheNativeLibraryRead()
    {
        var payload = Enumerable.Range(0, 132).Select(i => (byte)i).ToArray();
        var library = new FakeHkdfGuardKmsLibrary { OpenFilePayloadToEmit = payload };

        var bytes = library.OpenFile(@"C:\keys\dek.bin");

        Assert.Equal(payload, bytes);
        Assert.Equal(@"C:\keys\dek.bin", library.LastOpenFilePath);
    }

    [Fact]
    public void OpenFile_PassesABufferLargeEnoughForEveryPlatformsWrappedDek()
    {
        var payload = new byte[Abstractions.WrappedKeyLimits.MaxBytes];
        var library = new FakeHkdfGuardKmsLibrary { OpenFilePayloadToEmit = payload };

        Assert.Equal(payload.Length, library.OpenFile("dek.bin").Length);
    }

    public static TheoryData<int, Type> OpenFileFailures => new()
    {
        { AbstractHkdfGuardKmsLibrary.ErrFileNotFound, typeof(FileNotFoundException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileAccessDenied, typeof(UnauthorizedAccessException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileUntrusted, typeof(UnauthorizedAccessException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileTooShort, typeof(InvalidDataException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileTooLong, typeof(InvalidDataException) },
        { AbstractHkdfGuardKmsLibrary.ErrFilePlaintextKey, typeof(InvalidDataException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileMalformed, typeof(InvalidDataException) },
        { AbstractHkdfGuardKmsLibrary.ErrFileIo, typeof(IOException) },
        { AbstractHkdfGuardKmsLibrary.ErrInvalidArgument, typeof(ArgumentException) },
        { AbstractHkdfGuardKmsLibrary.ErrInternalError, typeof(IOException) },
    };

    [Theory]
    [MemberData(nameof(OpenFileFailures))]
    public void OpenFile_TurnsEachRefusalIntoTheMatchingException(int status, Type expected)
    {
        var library = new FakeHkdfGuardKmsLibrary { OpenFileStatus = status };

        var thrown = Assert.Throws(expected, () => library.OpenFile(@"C:\keys\dek.bin"));

        Assert.Contains(@"C:\keys\dek.bin", thrown.Message);
        Assert.Contains($"status {status}", thrown.Message);
        Assert.Contains(library.DescribeStatus(status)!, thrown.Message);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(Abstractions.WrappedKeyLimits.MaxBytes + 1)]
    public void OpenFile_WhenTheNativeLibraryReportsACountOutsideTheBuffer_Throws(int reported)
    {
        var library = new FakeHkdfGuardKmsLibrary { OpenFileBytesReadOverride = reported };

        var thrown = Assert.Throws<System.Security.Cryptography.CryptographicException>(() => library.OpenFile("dek.bin"));

        Assert.Contains($"reported {reported} bytes read", thrown.Message);
    }

    [Fact]
    public void OpenFile_NamesTheMissingFile()
    {
        var library = new FakeHkdfGuardKmsLibrary { OpenFileStatus = AbstractHkdfGuardKmsLibrary.ErrFileNotFound };

        var thrown = Assert.Throws<FileNotFoundException>(() => library.OpenFile("missing.bin"));

        Assert.Equal("missing.bin", thrown.FileName);
    }

    [Fact]
    public void OpenFile_SaysWhenAStatusIsUnknown()
    {
        var library = new FakeHkdfGuardKmsLibrary { OpenFileStatus = -63 };

        Assert.Contains("unknown status", Assert.Throws<IOException>(() => library.OpenFile("dek.bin")).Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void OpenFile_RefusesAMissingPath_BeforeReachingTheNativeLibrary(string? path)
    {
        var library = new FakeHkdfGuardKmsLibrary();

        Assert.ThrowsAny<ArgumentException>(() => library.OpenFile(path!));
        Assert.Equal(0, library.OpenFileCallCount);
    }
}
