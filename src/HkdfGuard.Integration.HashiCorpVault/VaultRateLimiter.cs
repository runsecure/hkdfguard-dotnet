using System.Diagnostics;

namespace HkdfGuard.Integration.HashiCorpVault;

/// <summary>
/// A token bucket, as Go's rate.Limiter: up to <see cref="Burst"/> requests at once, then
/// <see cref="RequestsPerSecond"/>. A request waits for its turn rather than failing. Thread-safe;
/// several clients may share one.
/// </summary>
public sealed class VaultRateLimiter
{
    private readonly Lock _lock = new();
    private double _tokens;
    private long _updated;

    /// <param name="requestsPerSecond">How many requests a second, once the burst is spent; may be fractional.</param>
    /// <param name="burst">How many requests may go at once.</param>
    /// <exception cref="ArgumentOutOfRangeException">requestsPerSecond isn't a positive number, or burst isn't positive</exception>
    public VaultRateLimiter(double requestsPerSecond, int burst)
    {
        if (!double.IsFinite(requestsPerSecond) || requestsPerSecond <= 0)
            throw new ArgumentOutOfRangeException(nameof(requestsPerSecond), requestsPerSecond, "The rate must be a positive number.");
        ArgumentOutOfRangeException.ThrowIfLessThan(burst, 1);

        RequestsPerSecond = requestsPerSecond;
        Burst = burst;
        _tokens = burst;
        _updated = Stopwatch.GetTimestamp();
    }

    /// <summary>Requests a second, once the burst is spent.</summary>
    public double RequestsPerSecond { get; }

    /// <summary>Requests that may go at once.</summary>
    public int Burst { get; }

    /// <summary>Waits until a request may be sent, and counts it.</summary>
    internal async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        TimeSpan wait;
        lock (_lock)
        {
            var now = Stopwatch.GetTimestamp();
            _tokens = Math.Min(Burst, _tokens + Stopwatch.GetElapsedTime(_updated, now).TotalSeconds * RequestsPerSecond);
            _updated = now;

            // Reserved now, waited for after: a request behind it waits for its own turn as well.
            _tokens--;
            wait = _tokens >= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(-_tokens / RequestsPerSecond);
        }

        if (wait <= TimeSpan.Zero)
            return;

        try
        {
            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The request won't be sent: give its turn back.
            lock (_lock)
                _tokens = Math.Min(Burst, _tokens + 1);
            throw;
        }
    }
}
