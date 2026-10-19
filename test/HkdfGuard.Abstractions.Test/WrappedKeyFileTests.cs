namespace HkdfGuard.Abstractions.Test;

public sealed class WrappedKeyFileTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("hkdfguard-wrapped-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Write(byte[] contents)
    {
        var path = Path.Combine(_directory, $"{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, contents);
        return path;
    }

    [Theory]
    [InlineData(1)]
    [InlineData(132)]
    [InlineData(WrappedKeyLimits.MaxBytes)]
    public async Task ReadAsync_ReturnsExactlyTheFilesBytes(int size)
    {
        var contents = Enumerable.Range(0, size).Select(i => (byte)i).ToArray();

        Assert.Equal(contents, await WrappedKeyFile.ReadAsync(Write(contents)));
    }

    [Fact]
    public async Task ReadAsync_RefusesAnEmptyFile()
    {
        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await WrappedKeyFile.ReadAsync(Write([])));

        Assert.Contains("is empty", thrown.Message);
    }

    [Theory]
    [InlineData(WrappedKeyLimits.MaxBytes + 1)]
    [InlineData(1_000_000)]
    public async Task ReadAsync_RefusesAFileOverTheLimit(int size)
    {
        var thrown = await Assert.ThrowsAsync<InvalidDataException>(async () => await WrappedKeyFile.ReadAsync(Write(new byte[size])));

        Assert.Contains("WrappedKeyLimits.MaxBytes", thrown.Message);
    }

    [Fact]
    public async Task ReadAsync_AMissingFile_IsNotFound()
        => await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await WrappedKeyFile.ReadAsync(Path.Combine(_directory, "missing.bin")));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ReadAsync_RefusesAMissingPath(string? path)
        => await Assert.ThrowsAnyAsync<ArgumentException>(async () => await WrappedKeyFile.ReadAsync(path!));

    [Fact]
    public async Task ReadAsync_HonorsCancellation()
        => await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await WrappedKeyFile.ReadAsync(Write([1, 2, 3]), new CancellationToken(true)));

    /// <summary>A key wrapper that doesn't read key files itself.</summary>
    private sealed class PlainKeyWrapper : IKeyWrapper
    {
        public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public async Task AKeyWrapper_ByDefault_ReadsKeyFilesWithOrdinaryFileIo()
    {
        IKeyWrapper wrapper = new PlainKeyWrapper();

        Assert.Equal(new byte[] { 7, 8, 9 }, await wrapper.ReadKeyFileAsync(Write([7, 8, 9])));
        await Assert.ThrowsAsync<InvalidDataException>(async () => await wrapper.ReadKeyFileAsync(Write([])));
    }
}
