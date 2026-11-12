using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.EncryptedConfiguration;
using HkdfGuard.Integration.ConfigurationResolver;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// ProtectedConfigurationRoot - protected values held in ordinary IConfiguration, decrypted on
/// lookup. Each lookup reads the configuration value, creates a protector for the key's purpose,
/// parses the envelope and decrypts. PlainValue is a key whose value isn't protected at all, which
/// is reported missing - the format provider rejecting it is part of what that costs, so a caller
/// probing ordinary settings through the root pays it on each one. MissingKey has no value.
/// </summary>
[MemoryDiagnoser]
public class ProtectedConfigurationRootBenchmarks
{
    private const string Key = "ConnectionStrings:Primary";

    private KeyRing _ring = null!;
    private ProtectedConfigurationRoot _root = null!;
    private char[] _charResult = null!;
    private byte[] _byteResult = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        // Encrypted as a release pipeline writes configuration, read through a ring holding that key.
        using var pipeline = new AesGcmPipelineDataProtector(BenchmarkKeys.LargeFormat(), 1);
        _ring = await BenchmarkKeys.CreateRingAsync(Convert.FromBase64String(pipeline.GetKeyAsBase64().ToString()));

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [Key] = pipeline.Encrypt("Server=db.internal;User Id=app;Password=s3cret-value;", Key),
                ["Logging:LogLevel:Default"] = "Information",
            })
            .Build();
        _root = new ProtectedConfigurationRoot(configuration, _ring);
        _root.TryGetMaxDecryptedLength(Key, out var max);
        _charResult = new char[max];
        _byteResult = new byte[max];
    }

    [Benchmark(Baseline = true)]
    public int DecryptChars() => _root.Decrypt(Key, _charResult);

    [Benchmark]
    public int DecryptBytes() => _root.Decrypt(Key, _byteResult);

    [Benchmark]
    public bool TryGetMaxDecryptedLength() => _root.TryGetMaxDecryptedLength(Key, out _);

    [Benchmark]
    public int PlainValue() => _root.Decrypt("Logging:LogLevel:Default", _charResult);

    [Benchmark]
    public int MissingKey() => _root.Decrypt("No:Such:Key", _charResult);

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}

/// <summary>
/// ResolvingProtectedCacheCollection - a ProtectedCacheCollection that expands "${name}" items in
/// a template source's values. CachedTemplate is the steady state: a template resolved once,
/// re-encrypted and cached, so each later lookup only decrypts it. ResolveTemplate invalidates it
/// first, so each lookup resolves again: the template and each of its items decrypted from the
/// sources, the result assembled in pinned memory, encrypted and cached. PlainValue has no items and
/// is answered by its source. ValueProvider is ProtectedCacheValueProvider - a protected cache as a
/// ConfigurationResolver value provider - answering one item.
/// </summary>
[MemoryDiagnoser]
public class ResolvingProtectedCacheCollectionBenchmarks
{
    private KeyRing _ring = null!;
    private ResolvingProtectedCacheCollection _collection = null!;
    private ProtectedCacheValueProvider _valueProvider = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        var source = new ProtectedCache(_ring);
        source.Add("conn", "Host=${host};Port=${port};User=${user};Password=${password}".ToCharArray());
        source.Add("host", "db.internal.example.com".ToCharArray());
        source.Add("port", "5432".ToCharArray());
        source.Add("user", "application".ToCharArray());
        source.Add("password", BenchmarkKeys.Text(32).ToCharArray());

        _collection = new ResolvingProtectedCacheCollection(_ring).AddTemplateSource(source);
        _valueProvider = new ProtectedCacheValueProvider(source);
        _result = new char[256];
        if (_collection.Decrypt("conn", _result) == 0)
            throw new InvalidOperationException("The template didn't resolve.");
    }

    [Benchmark(Baseline = true)]
    public int CachedTemplate() => _collection.Decrypt("conn", _result);

    [Benchmark]
    public int ResolveTemplate()
    {
        _collection.Invalidate("conn");
        return _collection.Decrypt("conn", _result);
    }

    [Benchmark]
    public int PlainValue() => _collection.Decrypt("password", _result);

    [Benchmark]
    public int ValueProvider()
    {
        _valueProvider.TryGetChar("password", _result, out var written);
        return written;
    }

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}
