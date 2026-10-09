// EncryptedConfigurationDiagnosticsTests and ProtectedConfigurationRootTests both toggle the
// shared static HkdfDiagnostics.EnableSensitiveLogging flag, which every other test class's
// production code path also reads (the `if (EncryptedConfigurationDiagnostics.EnableSensitiveLogging)`
// gates throughout this library). xUnit parallelizes test classes by default, so without this,
// those classes race against each other - not a correctness risk (nothing else asserts on
// sensitive-logging output), but it makes code coverage measurement non-deterministic between runs.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
