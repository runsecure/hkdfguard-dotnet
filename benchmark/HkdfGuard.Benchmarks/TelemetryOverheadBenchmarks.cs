using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// What HkdfGuard's tracing costs once an application listens to it. Every other benchmark runs
/// with no ActivityListener, so each StartActivity returns null and telemetry costs almost nothing;
/// an application exporting traces makes every layer (the cache's decrypt, the key's, the
/// session's) create and stop a real Activity. Mode: None - no listener; Listening - every
/// HkdfGuard source sampled and recorded; Sensitive - also EnableSensitiveLogging, which adds the
/// name and lengths of each operation as tags. Measured through ProtectedCache.Decrypt and
/// AddOrUpdate, which pass through every layer.
/// </summary>
[MemoryDiagnoser]
public class TelemetryOverheadBenchmarks
{
    public enum TelemetryMode
    {
        None,
        Listening,
        Sensitive,
    }

    private const string Name = "ConnectionStrings:Primary";

    [Params(TelemetryMode.None, TelemetryMode.Listening, TelemetryMode.Sensitive)]
    public TelemetryMode Mode { get; set; }

    private HkdfGuardActivityListener? _listener;
    private KeyRing _ring = null!;
    private ProtectedCache _cache = null!;
    private char[] _template = null!;
    private char[] _scratch = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        if (Mode != TelemetryMode.None)
            _listener = new HkdfGuardActivityListener();
        if (Mode == TelemetryMode.Sensitive)
            SetSensitiveLogging(true);

        _ring = await BenchmarkKeys.CreateRingAsync();
        _cache = new ProtectedCache(_ring);
        _template = BenchmarkKeys.Text(64).ToCharArray();
        _scratch = new char[_template.Length];
        _cache.AddOrUpdate(Name, (char[])_template.Clone());
        _result = new char[128];
    }

    // Cache, DataProtection and EncryptedConfiguration share Root's flag; the crypto provider has its own.
    private static void SetSensitiveLogging(bool enabled)
    {
        HkdfGuardTelemetry.Root.EnableSensitiveLogging = enabled;
        HkdfGuardTelemetry.CryptoProviderAesGcm256.EnableSensitiveLogging = enabled;
    }

    [Benchmark(Baseline = true)]
    public int Decrypt() => _cache.Decrypt(Name, _result);

    [Benchmark]
    public void AddOrUpdate()
    {
        _template.CopyTo(_scratch, 0);
        _cache.AddOrUpdate(Name, _scratch);
    }

    [GlobalCleanup]
    public async Task GlobalCleanup()
    {
        await _ring.DisposeAsync();
        SetSensitiveLogging(false);
        _listener?.Dispose();
    }
}
