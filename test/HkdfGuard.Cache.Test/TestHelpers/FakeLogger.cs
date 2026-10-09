using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// An ILogger&lt;T&gt; that records every log call instead of writing anywhere - lets tests assert
/// on ProtectedCache's optional-logger pattern (HkdfGuardLoggerExtensions) without depending on a
/// real logging provider.
/// </summary>
internal sealed class FakeLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, EventId EventId, string Message, Exception? Exception)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Entries.Add((logLevel, eventId, formatter(state, exception), exception));
}
