using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// An IProtectedReadOnlyCache whose every member throws - exercises ProtectedCacheCollection's
/// catch blocks without depending on a specific real failure mode.
/// </summary>
internal sealed class ThrowingReadOnlyCache(Exception exception) : IProtectedReadOnlyCache
{
    public int Decrypt(string name, Span<byte> result) => throw exception;
    public int Decrypt(string name, Span<char> result) => throw exception;
    public bool TryGetMaxDecryptedLength(string name, out int maxLength) => throw exception;
}
