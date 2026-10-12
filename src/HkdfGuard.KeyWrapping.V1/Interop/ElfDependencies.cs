using System.Buffers.Binary;
using System.Security;
using System.Text;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to load
/// - from a 64-bit little-endian ELF file (x86-64 and arm64 Linux). Only the ELF header, the
/// program headers, the dynamic segment and its string table are read. Anything malformed is
/// refused: the caller is deciding whether to trust what the file pulled into the process.
/// </summary>
internal static class ElfDependencies
{
    private const int HeaderSize = 64;
    private const int ProgramHeaderSize = 56;
    private const int DynamicEntrySize = 16;
    private const int MaxProgramHeaders = 4096;
    private const int MaxSegmentBytes = 1 << 20;

    private const uint PtLoad = 1;
    private const uint PtDynamic = 2;

    private const long DtNull = 0;
    private const long DtNeeded = 1;
    private const long DtStrTab = 5;
    private const long DtStrSz = 10;

    /// <summary>The DT_NEEDED names of the ELF file at <paramref name="path"/>, in file order.</summary>
    /// <exception cref="SecurityException">The file is not a well-formed 64-bit little-endian ELF object.</exception>
    public static IReadOnlyList<string> ReadNeeded(string path)
    {
        using var file = File.OpenHandle(path);
        return ReadNeeded(path, (offset, count) =>
        {
            var buffer = new byte[count];
            var total = 0;
            while (total < count)
            {
                var read = RandomAccess.Read(file, buffer.AsSpan(total), offset + total);
                if (read == 0)
                    break;
                total += read;
            }

            return total == count ? buffer : null;
        });
    }

    /// <param name="path">The file's name, for messages.</param>
    /// <param name="read">Reads exactly count bytes at offset, or returns null if the file is shorter.</param>
    internal static IReadOnlyList<string> ReadNeeded(string path, Func<long, int, byte[]?> read)
    {
        var header = Read(path, read, 0, HeaderSize, "ELF header");
        if (header[0] != 0x7F || header[1] != (byte)'E' || header[2] != (byte)'L' || header[3] != (byte)'F')
            throw Malformed(path, "it is not an ELF file");
        if (header[4] != 2 || header[5] != 1)
            throw Malformed(path, "it is not a 64-bit little-endian ELF file");

        var programHeaderOffset = ToOffset(path, BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32)));
        var programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(54));
        var programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(56));
        if (programHeaderSize < ProgramHeaderSize || programHeaderCount is 0 or > MaxProgramHeaders)
            throw Malformed(path, "its program header table is malformed");

        var programHeaders = Read(path, read, programHeaderOffset, programHeaderSize * programHeaderCount, "program headers");
        var loads = new List<(ulong VirtualAddress, ulong FileSize, long Offset)>();
        (long Offset, int Size)? dynamic = null;
        for (var i = 0; i < programHeaderCount; i++)
        {
            var entry = programHeaders.AsSpan(i * programHeaderSize, programHeaderSize);
            var type = BinaryPrimitives.ReadUInt32LittleEndian(entry);
            var offset = ToOffset(path, BinaryPrimitives.ReadUInt64LittleEndian(entry[8..]));
            var virtualAddress = BinaryPrimitives.ReadUInt64LittleEndian(entry[16..]);
            var fileSize = BinaryPrimitives.ReadUInt64LittleEndian(entry[32..]);

            if (type == PtLoad)
                loads.Add((virtualAddress, fileSize, offset));
            else if (type == PtDynamic)
                dynamic = (offset, ToSize(path, fileSize, "dynamic segment"));
        }

        if (dynamic is not { } segment)
            return [];

        var neededOffsets = new List<ulong>();
        ulong? stringTableAddress = null;
        ulong? stringTableSize = null;
        var entries = Read(path, read, segment.Offset, segment.Size - segment.Size % DynamicEntrySize, "dynamic segment");
        for (var at = 0; at + DynamicEntrySize <= entries.Length; at += DynamicEntrySize)
        {
            var tag = BinaryPrimitives.ReadInt64LittleEndian(entries.AsSpan(at));
            var value = BinaryPrimitives.ReadUInt64LittleEndian(entries.AsSpan(at + 8));
            if (tag == DtNull)
                break;
            if (tag == DtNeeded)
                neededOffsets.Add(value);
            else if (tag == DtStrTab)
                stringTableAddress = value;
            else if (tag == DtStrSz)
                stringTableSize = value;
        }

        if (neededOffsets.Count == 0)
            return [];
        if (stringTableAddress is not { } address || stringTableSize is not { } size)
            throw Malformed(path, "it names dependencies but has no string table");

        // DT_STRTAB is a virtual address; the PT_LOAD segment containing it maps it to the file.
        var containing = loads.FirstOrDefault(l => address >= l.VirtualAddress && address - l.VirtualAddress < l.FileSize);
        if (containing == default)
            throw Malformed(path, "its string table lies outside every loaded segment");

        var strings = Read(path, read, checked(containing.Offset + (long)(address - containing.VirtualAddress)), ToSize(path, size, "string table"), "string table");
        var names = new List<string>(neededOffsets.Count);
        foreach (var offset in neededOffsets)
        {
            var end = offset < (ulong)strings.Length ? Array.IndexOf(strings, (byte)0, (int)offset) : -1;
            if (end < 0)
                throw Malformed(path, "a dependency name runs past its string table");

            names.Add(Encoding.UTF8.GetString(strings, (int)offset, end - (int)offset));
        }

        return names;
    }

    private static byte[] Read(string path, Func<long, int, byte[]?> read, long offset, int count, string what)
        => read(offset, count) is { } bytes && bytes.Length == count ? bytes : throw Malformed(path, $"its {what} runs past the end of the file");

    private static long ToOffset(string path, ulong value)
        => value <= long.MaxValue ? (long)value : throw Malformed(path, "a file offset is out of range");

    private static int ToSize(string path, ulong value, string what)
        => value <= MaxSegmentBytes ? (int)value : throw Malformed(path, $"its {what} is implausibly large");

    private static SecurityException Malformed(string path, string reason)
        => new($"'{path}' is not a well-formed ELF shared object: {reason}.");
}
