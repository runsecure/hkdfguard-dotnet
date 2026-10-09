using System.Diagnostics.Metrics;

namespace HkdfGuard.Diagnostics;

/// <summary>
/// Cache component instruments, built on HkdfGuardTelemetry.Cache.Meter. Operations counts every
/// ProtectedCache Add/AddOrUpdate call, tagged with AttributeNames.OperationName (which
/// ActivityNames.Cache constant ran) and AttributeNames.Result ("success" or "error").
/// </summary>
public static class CacheMetrics
{
    public static readonly Counter<long> Operations = HkdfGuardTelemetry.Cache.Meter.CreateCounter<long>(
        MetricNames.Cache.Operations,
        unit: "{operation}",
        description: "Number of ProtectedCache operations, tagged by operation and result.");
}
