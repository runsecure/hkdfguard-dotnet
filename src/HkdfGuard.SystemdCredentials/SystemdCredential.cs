using HkdfGuard.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace HkdfGuard.SystemdCredentials;

/// <summary>
/// A decrypted credential's value, in pinned memory the GC never copies. Dispose it as soon as the
/// value has been used: that zeroes it, and any read afterwards throws.
/// </summary>
public sealed class SystemdCredential : IDisposable
{
    /// <summary>The largest credential read: systemd's own limit on a credential's size, 1 MiB.</summary>
    public const int MaxLength = 1024 * 1024;

    private const int InitialBufferLength = 4 * 1024;

    private readonly byte[] _buffer;
    private bool _disposed;

    private SystemdCredential(byte[] buffer, int length)
    {
        _buffer = buffer;
        Length = length;
    }

    /// <summary>How many bytes the value is.</summary>
    public int Length { get; }

    /// <summary>The value; valid until the credential is disposed.</summary>
    /// <exception cref="ObjectDisposedException">The credential has been disposed</exception>
    public ReadOnlySpan<byte> Value
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer.AsSpan(0, Length);
        }
    }

    /// <summary>Zeroes the value. Safe to call more than once.</summary>
    public void Dispose()
    {
        _disposed = true;
        ArrayUtility.ZeroMemory(_buffer);
    }

    /// <summary>Reads stream to its end into pinned memory, growing it as needed and zeroing each smaller buffer.</summary>
    /// <exception cref="InvalidDataException">It is longer than <see cref="MaxLength"/></exception>
    internal static async Task<SystemdCredential> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = ArrayUtility.AllocatePinned<byte>(InitialBufferLength);
        var length = 0;
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                length += read;
                if (length < buffer.Length)
                    continue;
                if (buffer.Length > MaxLength)
                    throw new InvalidDataException($"The credential is longer than systemd's {MaxLength}-byte limit.");

                var larger = ArrayUtility.AllocatePinned<byte>(Math.Min(buffer.Length * 2, MaxLength + 1));
                buffer.AsSpan(0, length).CopyTo(larger);
                ArrayUtility.ZeroMemory(buffer);
                buffer = larger;
            }

            return new SystemdCredential(buffer, length);
        }
        catch
        {
            ArrayUtility.ZeroMemory(buffer);
            throw;
        }
    }

    /// <summary>
    /// Reads the file at path whole into pinned memory, unbuffered, so nothing but the kernel's page
    /// cache holds the value on the way.
    /// </summary>
    /// <exception cref="InvalidDataException">It is longer than <see cref="MaxLength"/></exception>
    internal static SystemdCredential ReadFile(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ReadFile(handle);
    }

    internal static SystemdCredential ReadFile(SafeFileHandle handle)
    {
        var length = RandomAccess.GetLength(handle);
        if (length > MaxLength)
            throw new InvalidDataException($"The credential is longer than systemd's {MaxLength}-byte limit.");

        var buffer = ArrayUtility.AllocatePinned<byte>((int)length);
        var read = 0;
        try
        {
            int count;
            while (read < buffer.Length && (count = RandomAccess.Read(handle, buffer.AsSpan(read), read)) > 0)
                read += count;
            return new SystemdCredential(buffer, read);
        }
        catch
        {
            ArrayUtility.ZeroMemory(buffer);
            throw;
        }
    }
}
