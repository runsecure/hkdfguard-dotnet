using System.Buffers;
using HkdfGuard.Abstractions;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// A growable buffer in pinned memory that is zeroed when it grows and when it's disposed: for
/// request and response bodies, which can hold tokens and secrets. The GC never moves it, so no copy
/// is left behind.
/// </summary>
internal sealed class SecureBufferWriter : IBufferWriter<byte>, IDisposable
{
    private const int MinimumCapacity = 256;

    // Grown into as the body arrives: a Content-Length doesn't get to claim more memory up front.
    private const int MaximumInitialCapacity = 1024 * 1024;

    private byte[] _buffer;
    private int _written;

    public SecureBufferWriter(long? expectedLength = null)
        => _buffer = ArrayUtility.AllocatePinned<byte>((int)Math.Clamp(expectedLength ?? 0, MinimumCapacity, MaximumInitialCapacity));

    public ReadOnlyMemory<byte> WrittenMemory => _buffer.AsMemory(0, _written);

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (count > _buffer.Length - _written)
            throw new InvalidOperationException("Advanced past the end of the buffer.");
        _written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Reserve(sizeHint);
        return _buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Reserve(sizeHint);
        return _buffer.AsSpan(_written);
    }

    /// <summary>Reads stream to its end into the buffer.</summary>
    public async Task ReadFromAsync(Stream stream, CancellationToken cancellationToken)
    {
        while (true)
        {
            var read = await stream.ReadAsync(GetMemory(8192), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return;
            Advance(read);
        }
    }

    public void Dispose()
    {
        ArrayUtility.ZeroMemory(_buffer);
        _written = 0;
    }

    private void Reserve(int sizeHint)
    {
        sizeHint = Math.Max(sizeHint, 1);
        if (_buffer.Length - _written >= sizeHint)
            return;

        var larger = ArrayUtility.AllocatePinned<byte>(checked(Math.Max(_buffer.Length * 2, _written + sizeHint)));
        _buffer.AsSpan(0, _written).CopyTo(larger);
        ArrayUtility.ZeroMemory(_buffer);
        _buffer = larger;
    }
}
