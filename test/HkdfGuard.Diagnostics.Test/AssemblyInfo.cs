// These tests set HkdfGuardTelemetry components' shared/static EnableSensitiveLogging flags,
// which every other test class here also reads. xUnit parallelizes test classes by default, so
// without this, those tests race against each other - not a correctness risk (nothing else
// asserts on sensitive-logging output outside this assembly), but it makes results
// non-deterministic between runs.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
