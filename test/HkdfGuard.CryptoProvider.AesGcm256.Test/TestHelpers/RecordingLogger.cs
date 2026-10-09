using Microsoft.Extensions.Logging;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;

/// <summary>
/// An ILogger&lt;T&gt; that records every entry. Thread-safe: the provider logs from its background
/// refresh loop while the test thread reads.
/// </summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    private readonly Lock _gate = new();
    private readonly List<(LogLevel Level, int EventId, string Message, Exception? Exception)> _entries = [];

    public IReadOnlyList<(LogLevel Level, int EventId, string Message, Exception? Exception)> Entries
    {
        get
        {
            lock (_gate)
                return [.. _entries];
        }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_gate)
            _entries.Add((logLevel, eventId.Id, formatter(state, exception), exception));
    }
}
