using HkdfGuard.Abstractions;

namespace HkdfGuard.Pipeline;

/// <summary>Reads a response body that holds a secret into pinned memory, for a pipeline writer to take it from.</summary>
public static class PinnedBody
{
    /// <summary>The largest body read: far beyond any secret store's response, so a larger one is refused.</summary>
    public const int MaxLength = 1024 * 1024;

    private const int InitialBufferLength = 16 * 1024;

    /// <summary>
    /// Reads body to its end into pinned memory - never somewhere the GC can copy it, nor a pooled
    /// array - growing it as needed, each smaller buffer zeroed. body is read but not disposed.
    /// </summary>
    /// <returns>The buffer, which the caller must zero, and how much of it the body filled</returns>
    /// <exception cref="ArgumentNullException">body is null</exception>
    /// <exception cref="InvalidDataException">The body is <see cref="MaxLength"/> bytes or more</exception>
    public static async Task<(byte[] Buffer, int Length)> ReadAsync(Stream body, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(body);
        var buffer = ArrayUtility.AllocatePinned<byte>(InitialBufferLength);
        var length = 0;
        try
        {
            int read;
            while ((read = await body.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                length += read;
                if (length < buffer.Length)
                    continue;
                if (buffer.Length >= MaxLength)
                    throw new InvalidDataException($"The response body is {MaxLength} bytes or more.");

                var larger = ArrayUtility.AllocatePinned<byte>(Math.Min(buffer.Length * 2, MaxLength));
                buffer.AsSpan(0, length).CopyTo(larger);
                ArrayUtility.ZeroMemory(buffer);
                buffer = larger;
            }

            return (buffer, length);
        }
        catch
        {
            ArrayUtility.ZeroMemory(buffer);
            throw;
        }
    }
}
