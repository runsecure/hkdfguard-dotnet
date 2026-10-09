using HkdfGuard.CryptoProvider.AesGcm256.Test.TestHelpers;

namespace HkdfGuard.CryptoProvider.AesGcm256.Test;

/// <summary>
/// A provider created on a thread with a single-threaded SynchronizationContext (a UI thread,
/// classic ASP.NET) must still dispose. The refresh loop starts on the creating thread; if it
/// captured that context, cancelling it would post its continuation back to a context that is
/// blocked in Dispose - a deadlock.
/// </summary>
public class SynchronizationContextTests
{
    [Fact]
    public async Task Dispose_OfAProviderCreatedUnderAContextThatNeverRunsPostedWork_Completes()
    {
        var previous = SynchronizationContext.Current;
        AesGcmCryptoProvider provider;
        try
        {
            SynchronizationContext.SetSynchronizationContext(new NeverRunsContext());
            // The fake wrapper completes synchronously, so the whole creation - and the start of
            // the refresh loop - runs right here, under the context.
#pragma warning disable xUnit1031 // Blocking is the point: this thread must be the one carrying the context.
            provider = AesGcmCryptoProvider.CreateAsync(new FakeKeyWrapper(), "wrapped"u8.ToArray(), 60)
                .GetAwaiter().GetResult();
#pragma warning restore xUnit1031
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        // Before the fix the loop's continuation was posted to NeverRunsContext and lost, so
        // Dispose blocked forever; run it on another thread so a regression fails, not hangs.
        var dispose = Task.Run(provider.Dispose);
        var disposed = await Task.WhenAny(dispose, Task.Delay(TimeSpan.FromSeconds(10))) == dispose;

        Assert.True(disposed, "Dispose deadlocked waiting on a continuation posted to the creating thread's context.");
    }

    // Models a UI context whose thread is blocked: anything posted to it never runs.
    private sealed class NeverRunsContext : SynchronizationContext
    {
        public override void Post(SendOrPostCallback d, object? state)
        {
        }

        public override SynchronizationContext CreateCopy() => this;
    }
}
