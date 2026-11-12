using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// ProtectedCacheCollection - sources checked in the order added, first answer wins. A name held
/// by the last source pays a miss in every source before it, and a name held by none pays all of
/// them; SourceCount shows how that grows. Every source here is an in-memory ProtectedCache, so this
/// is the collection's own overhead (and each source's miss); a file-backed or remote source's miss
/// costs what FileBackedCacheBenchmarks and RemoteSecretCacheBenchmarks show.
/// </summary>
[MemoryDiagnoser]
public class ProtectedCacheCollectionBenchmarks
{
    [Params(1, 4, 8)]
    public int SourceCount { get; set; }

    private KeyRing _ring = null!;
    private ProtectedCacheCollection _collection = null!;
    private char[] _result = null!;
    private string _lastName = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        _collection = new ProtectedCacheCollection();
        for (var i = 0; i < SourceCount; i++)
        {
            var source = new ProtectedCache(_ring);
            source.Add($"Only{i}", BenchmarkKeys.Text(32).ToCharArray());
            _collection.Add(source);
        }

        _result = new char[64];
        _lastName = $"Only{SourceCount - 1}";
    }

    [Benchmark]
    public int HitInFirstSource() => _collection.Decrypt("Only0", _result);

    [Benchmark]
    public int HitInLastSource() => _collection.Decrypt(_lastName, _result);

    [Benchmark]
    public int MissInEverySource() => _collection.Decrypt("Missing", _result);

    [Benchmark]
    public ValueTask<int> HitInLastSourceAsync() => _collection.DecryptAsync(_lastName, _result.AsMemory());

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}
