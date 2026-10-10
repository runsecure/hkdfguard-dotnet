namespace HkdfGuard.Abstractions;

/// <summary>
/// The refresh-failure policy's shared default. A provider re-reveals its key through the KEK on
/// a schedule; after this many consecutive failed attempts it fails closed - zeroes the key and
/// refuses every operation until a refresh succeeds - so revoking the KEK reaches a running
/// process. Everything that takes a <c>maxRefreshFailures</c> defaults to this; passing null
/// explicitly opts into failing open.
/// </summary>
public static class RefreshFailurePolicy
{
    /// <summary>Consecutive failed refreshes tolerated before failing closed, unless configured otherwise.</summary>
    public const int DefaultMaxRefreshFailures = 3;
}
