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

    /// <summary>
    /// The largest fail-closed limit accepted. 100 failures at the longest, 300-second refresh
    /// interval is about 8 h 20 min before a revoked KEK suspends key access; a larger value would
    /// quietly turn fail-closed into fail-open. To fail open, say so explicitly with null.
    /// </summary>
    public const int MaxAllowedRefreshFailures = 100;
}
