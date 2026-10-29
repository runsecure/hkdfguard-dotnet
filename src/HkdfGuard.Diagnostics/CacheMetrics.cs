using System.Diagnostics.Metrics;

namespace HkdfGuard.Diagnostics;

/// <summary>
/// Cache component instruments, built on HkdfGuardTelemetry.Cache.Meter. Operations counts every
/// ProtectedCache Add/AddOrUpdate call and every fetch a populating cache (e.g.
/// AzureKeyVaultSecretCache, AwsSecretsManagerSecretCache, GoogleSecretManagerSecretCache) makes on a miss, tagged with AttributeNames.OperationName (which
/// ActivityNames.Cache constant ran) and AttributeNames.Result ("success" or "error", or
/// "not_found" for a fetch whose source has no such value).
/// </summary>
public static class CacheMetrics
{
    public static readonly Counter<long> Operations = HkdfGuardTelemetry.Cache.Meter.CreateCounter<long>(
        MetricNames.Cache.Operations,
        unit: "{operation}",
        description: "Number of ProtectedCache operations, tagged by operation and result.");
}
