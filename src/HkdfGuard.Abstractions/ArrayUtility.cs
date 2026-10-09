using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace HkdfGuard.Abstractions;

public static class ArrayUtility
{
    /// <summary>
    /// Largest scratch buffer for secret bytes (plaintext, key material) that this library puts on
    /// the stack. Stack memory is never moved by the GC, so zeroing it reaches the only copy.
    /// Anything larger goes on the Pinned Object Heap instead (see <see cref="AllocatePinned{T}"/>),
    /// which is never moved either, rather than risk overflowing the stack - an uncatchable crash.
    /// 4 KiB covers every value DefaultFormatProvider accepts by default.
    /// </summary>
    public const int MaxStackBytes = 4096;

    /// <summary><see cref="MaxStackBytes"/> expressed in chars.</summary>
    public const int MaxStackChars = MaxStackBytes / sizeof(char);

    /// <summary>
    /// Allocates a zeroed array on the Pinned Object Heap, for secret material that must outlive a
    /// single stack frame (a key held by a session) or is too large for the stack. The GC never
    /// relocates it, so <see cref="ZeroMemory(Span{byte})"/> erases the only managed copy, where a
    /// normal array could leave stale, unzeroed copies behind after a compacting collection.
    /// </summary>
    public static T[] AllocatePinned<T>(int length) where T : unmanaged
        => GC.AllocateArray<T>(length, pinned: true);

    /// <summary>
    /// True if the span is empty or every byte is zero. Runs in time that depends only on the
    /// length, never on the contents, so it is safe to call on key material.
    /// </summary>
    public static bool IsNullOrEmpty(ReadOnlySpan<byte> input)
    {
        var accumulator = 0;
        foreach (var b in input)
            accumulator |= b;
        return accumulator == 0;
    }

    /// <summary>
    /// True if the span is empty or every char is '\0'. Runs in time that depends only on the
    /// length, never on the contents.
    /// </summary>
    public static bool IsNullOrEmpty(ReadOnlySpan<char> input)
    {
        var accumulator = 0;
        foreach (var c in input)
            accumulator |= c;
        return accumulator == 0;
    }

    /// <summary>
    /// Zeroes the span through CryptographicOperations.ZeroMemory, which the runtime guarantees
    /// is never optimized away (a plain loop or Clear could be, as dead stores).
    /// </summary>
    public static void ZeroMemory(Span<byte> input)
        => CryptographicOperations.ZeroMemory(input);

    /// <inheritdoc cref="ZeroMemory(Span{byte})"/>
    public static void ZeroMemory(Span<char> input)
        => CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(input));
}
