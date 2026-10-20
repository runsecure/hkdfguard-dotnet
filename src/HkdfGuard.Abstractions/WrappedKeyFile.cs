namespace HkdfGuard.Abstractions;

/// <summary>
/// Reads a wrapped-DEK key file with ordinary .NET file I/O - the default
/// <see cref="IKeyWrapper.ReadKeyFileAsync"/>, for key wrappers with no native library of their
/// own to read through (a remote KMS, say, or a test double). A wrapper backed by the native KMS
/// library reads through that library instead, which also checks who could have written the file.
/// </summary>
public static class WrappedKeyFile
{
    /// <summary>
    /// Reads a wrapped DEK, refusing an empty file or one over <see cref="WrappedKeyLimits.MaxBytes"/>.
    /// Never reads more than one byte past the limit, whatever the file's size - so a wrong path
    /// (a log, a device) or a file still growing can't make startup allocate an unbounded buffer.
    /// </summary>
    /// <param name="path">The key file's path.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The file's contents, still wrapped.</returns>
    /// <exception cref="InvalidDataException">The file is empty or larger than the limit</exception>
    /// <exception cref="IOException">The file can't be opened or read</exception>
    public static async ValueTask<byte[]> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);

        await using var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        });

        var buffer = new byte[WrappedKeyLimits.MaxBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length
               && (read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false)) > 0)
            total += read;

        if (total == 0)
            throw new InvalidDataException($"Key file '{path}' is empty.");
        if (total > WrappedKeyLimits.MaxBytes)
            throw new InvalidDataException(
                $"Key file '{path}' is larger than {WrappedKeyLimits.MaxBytes} bytes (WrappedKeyLimits.MaxBytes); a wrapped key never is.");

        return buffer[..total];
    }
}
