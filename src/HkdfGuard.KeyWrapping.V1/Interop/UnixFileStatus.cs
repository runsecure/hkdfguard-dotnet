namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>What lstat reports about one path: who owns it, its permissions, and its type.</summary>
internal readonly record struct UnixFileStatus(uint OwnerId, uint GroupId, UnixFileMode Permissions, UnixFileType Type);

internal enum UnixFileType
{
    Other,
    RegularFile,
    Directory,
    SymbolicLink,
}
