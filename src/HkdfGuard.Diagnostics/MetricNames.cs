namespace HkdfGuard.Diagnostics;

/// <summary>
/// Metric instrument names, following the same <c>hkdfguard.&lt;component&gt;.&lt;noun&gt;</c>
/// convention as <see cref="ActivityNames"/>.
/// </summary>
public static class MetricNames
{
    public static class Cache
    {
        public const string Operations = "hkdfguard.cache.operations";
    }
}
