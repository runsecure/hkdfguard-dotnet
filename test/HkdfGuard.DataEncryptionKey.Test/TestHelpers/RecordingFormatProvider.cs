using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// A real DefaultFormatProvider wrapped with call tracking, so a test can prove a component (e.g.
/// KeyRing/KeyRingBuilder) actually uses the specific IEncryptedFormatProvider instance it was
/// given, rather than some other one.
/// </summary>
internal sealed class RecordingFormatProvider : IEncryptedFormatProvider
{
    private readonly DefaultFormatProvider _inner = new();

    public bool FormatCalled { get; private set; }
    public bool ParseCalled { get; private set; }

    public string Format(KeyTrackingValue value)
    {
        FormatCalled = true;
        return _inner.Format(value);
    }

    public KeyTrackingValue Parse(ReadOnlySpan<char> encrypted)
    {
        ParseCalled = true;
        return _inner.Parse(encrypted);
    }

    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
        => _inner.GetMaxDecryptedLength(encrypted);
}
