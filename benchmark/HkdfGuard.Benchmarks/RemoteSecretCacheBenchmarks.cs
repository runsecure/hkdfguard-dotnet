using System.Text;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// A RemoteSecretCache whose "store" is a JSON response body held in memory, captured with
/// SecretJsonBody exactly as the AWS Secrets Manager (a top-level SecretString) and HashiCorp Vault
/// (keys under data.data) caches capture theirs - so a populate costs everything but the network.
/// </summary>
internal sealed class InMemoryRemoteSecretCache(IKeyRing keyRing, SecretNameMatching matching, bool vaultShaped)
    : RemoteSecretCache(keyRing, matching)
{
    private static readonly string[] VaultDataPath = ["data", "data"];

    public Dictionary<string, byte[]> Bodies { get; } = new(StringComparer.Ordinal);

    protected override bool IsValidName(string name) => name.Length > 0 && !name.Contains(':');

    protected override void Fetch(string name, SecretValueSink value)
    {
        if (!Bodies.TryGetValue(name, out var body))
            return;

        using var stream = new MemoryStream(body, writable: false);
        if (vaultShaped)
            SecretJsonBody.CaptureKeys(stream, value, VaultDataPath);
        else
            SecretJsonBody.Capture(stream, value, "SecretString", "SecretBinary");
    }

    /// <summary>An AWS-shaped body whose SecretString is a JSON object of <paramref name="keyCount"/> keys.</summary>
    public static byte[] AwsBody(int keyCount, int valueLength)
    {
        var inner = new StringBuilder("{");
        for (var i = 0; i < keyCount; i++)
            inner.Append(i == 0 ? "" : ",").Append($"\"key{i}\":\"{BenchmarkKeys.Text(valueLength)}\"");
        inner.Append('}');
        return Encoding.UTF8.GetBytes($"{{\"Name\":\"app-config\",\"SecretString\":{System.Text.Json.JsonSerializer.Serialize(inner.ToString())}}}");
    }

    /// <summary>A Vault KV v2-shaped body holding <paramref name="keyCount"/> keys under data.data.</summary>
    public static byte[] VaultBody(int keyCount, int valueLength)
    {
        var data = new StringBuilder("{");
        for (var i = 0; i < keyCount; i++)
            data.Append(i == 0 ? "" : ",").Append($"\"key{i}\":\"{BenchmarkKeys.Text(valueLength)}\"");
        data.Append('}');
        return Encoding.UTF8.GetBytes($"{{\"data\":{{\"data\":{data},\"metadata\":{{\"version\":3}}}}}}");
    }
}

/// <summary>
/// Lookups against a RemoteSecretCache that has already fetched: the steady state of every cloud
/// secret-store cache (AWS, Azure, Google, Vault), with no network. Each lookup maps the name to
/// its entry name (splitting off "#key", validating, and - with Exact matching - escaping upper
/// case) before ProtectedCacheBase's decrypt, so plain, keyed and Exact-matching lookups are
/// measured separately. RememberedMiss is a name the store didn't have, answered from the
/// remembered-miss list for MissLifetime rather than fetched again.
/// </summary>
[MemoryDiagnoser]
public class RemoteSecretCacheBenchmarks
{
    private KeyRing _ring = null!;
    private InMemoryRemoteSecretCache _ignoreCase = null!;
    private InMemoryRemoteSecretCache _exact = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        var body = InMemoryRemoteSecretCache.AwsBody(keyCount: 4, valueLength: 32);
        _ignoreCase = new InMemoryRemoteSecretCache(_ring, SecretNameMatching.IgnoreAsciiCase, vaultShaped: false);
        _ignoreCase.Bodies["app-config"] = body;
        _exact = new InMemoryRemoteSecretCache(_ring, SecretNameMatching.Exact, vaultShaped: false);
        _exact.Bodies["App-Config"] = body;
        _result = new char[512];

        // Populate every entry, and the remembered miss, before measuring.
        _ignoreCase.Decrypt("app-config", _result);
        _exact.Decrypt("App-Config", _result);
        _ignoreCase.Decrypt("missing", _result);
    }

    [Benchmark(Baseline = true)]
    public int HitWholeSecret() => _ignoreCase.Decrypt("app-config", _result);

    [Benchmark]
    public int HitKey() => _ignoreCase.Decrypt("app-config#key2", _result);

    [Benchmark]
    public int HitExactMatching() => _exact.Decrypt("App-Config", _result);

    [Benchmark]
    public int HitKeyExactMatching() => _exact.Decrypt("App-Config#key2", _result);

    [Benchmark]
    public ValueTask<int> HitKeyAsync() => _ignoreCase.DecryptAsync("app-config#key2", _result.AsMemory());

    [Benchmark]
    public int RememberedMiss() => _ignoreCase.Decrypt("missing", _result);

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}

/// <summary>
/// A RemoteSecretCache's first lookup of a secret: the fetch (here an in-memory JSON body), the
/// SecretJsonBody capture into pinned memory, and encrypting the whole value and every key it
/// holds into the cache - what a cold application pays per secret, minus the network round trip.
/// Each invocation looks up a secret not yet fetched, against a cache made fresh for each
/// iteration. KeyCount is how many keys the secret's JSON object holds: each becomes its own
/// encrypted entry.
/// </summary>
[MemoryDiagnoser]
[InvocationCount(Invocations)]
public class RemoteSecretCachePopulateBenchmarks
{
    private const int Invocations = 512;

    [Params(1, 16)]
    public int KeyCount { get; set; }

    private KeyRing _ring = null!;
    private byte[] _awsBody = null!;
    private byte[] _vaultBody = null!;
    private string[] _names = null!;
    private InMemoryRemoteSecretCache _cache = null!;
    private char[] _result = null!;
    private int _next;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        _awsBody = InMemoryRemoteSecretCache.AwsBody(KeyCount, valueLength: 32);
        _vaultBody = InMemoryRemoteSecretCache.VaultBody(KeyCount, valueLength: 32);
        _names = Enumerable.Range(0, Invocations).Select(i => $"secret{i}").ToArray();
        _result = new char[16 * 1024];
    }

    [IterationSetup(Target = nameof(PopulateAwsShaped))]
    public void SetupAws() => _cache = Fresh(_awsBody, vaultShaped: false);

    [IterationSetup(Target = nameof(PopulateVaultShaped))]
    public void SetupVault() => _cache = Fresh(_vaultBody, vaultShaped: true);

    private InMemoryRemoteSecretCache Fresh(byte[] body, bool vaultShaped)
    {
        var cache = new InMemoryRemoteSecretCache(_ring, SecretNameMatching.IgnoreAsciiCase, vaultShaped);
        foreach (var name in _names)
            cache.Bodies[name] = body;
        _next = 0;
        return cache;
    }

    /// <summary>AWS shape: the whole SecretString is an entry, and so is each of its keys.</summary>
    [Benchmark]
    public int PopulateAwsShaped() => _cache.Decrypt(_names[_next++], _result);

    /// <summary>Vault shape: each key under data.data is an entry; looked up by its first key.</summary>
    [Benchmark]
    public int PopulateVaultShaped() => _cache.Decrypt(_names[_next++] + "#key0", _result);

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}
