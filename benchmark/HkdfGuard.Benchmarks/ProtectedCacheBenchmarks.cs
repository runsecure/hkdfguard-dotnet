using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// ProtectedCache - the in-memory cache every application lookup ends at, and ProtectedCacheBase,
/// which every other cache (remote, file-backed, resolving) stores through. Covers storing
/// (AddOrUpdate, bytes and chars), the lookups (Decrypt to bytes and to chars, DecryptAsync,
/// TryGetMaxDecryptedLength) and a miss. A lookup builds the name-binding AAD on every call - on the
/// stack up to 512 bytes, on the heap past that - so *LongName uses a 600-character name to show
/// that switch; *OtherCase looks the name up in a different case, through the ASCII
/// case-insensitive comparer.
/// </summary>
[MemoryDiagnoser]
public class ProtectedCacheBenchmarks
{
    private const string Name = "ConnectionStrings:Primary";
    private static readonly string LongName = "Section:" + new string('k', 600);

    [Params(32, 4096)]
    public int ValueSize { get; set; }

    private KeyRing _ring = null!;
    private ProtectedCache _cache = null!;
    private byte[] _bytesTemplate = null!;
    private byte[] _bytesScratch = null!;
    private char[] _charsTemplate = null!;
    private char[] _charsScratch = null!;
    private byte[] _byteResult = null!;
    private char[] _charResult = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        _cache = new ProtectedCache(_ring);
        _bytesTemplate = RandomNumberGenerator.GetBytes(ValueSize);
        _bytesScratch = new byte[ValueSize];
        _charsTemplate = BenchmarkKeys.Text(ValueSize).ToCharArray();
        _charsScratch = new char[ValueSize];

        // AddOrUpdate zeroes what it's given, so each store is from a copy.
        _cache.AddOrUpdate(Name, (char[])_charsTemplate.Clone());
        _cache.AddOrUpdate(LongName, (char[])_charsTemplate.Clone());
        _cache.TryGetMaxDecryptedLength(Name, out var max);
        _byteResult = new byte[max];
        _charResult = new char[max];
    }

    [Benchmark]
    public void AddOrUpdateBytes()
    {
        _bytesTemplate.CopyTo(_bytesScratch, 0);
        _cache.AddOrUpdate("Bytes", _bytesScratch);
    }

    [Benchmark]
    public void AddOrUpdateChars()
    {
        _charsTemplate.CopyTo(_charsScratch, 0);
        _cache.AddOrUpdate("Chars", _charsScratch);
    }

    [Benchmark]
    public int DecryptBytes() => _cache.Decrypt(Name, _byteResult);

    [Benchmark]
    public int DecryptChars() => _cache.Decrypt(Name, _charResult);

    [Benchmark]
    public ValueTask<int> DecryptCharsAsync() => _cache.DecryptAsync(Name, _charResult.AsMemory());

    [Benchmark]
    public int DecryptCharsOtherCase() => _cache.Decrypt("connectionstrings:PRIMARY", _charResult);

    [Benchmark]
    public int DecryptCharsLongName() => _cache.Decrypt(LongName, _charResult);

    [Benchmark]
    public bool TryGetMaxDecryptedLength() => _cache.TryGetMaxDecryptedLength(Name, out _);

    [Benchmark]
    public int DecryptMiss() => _cache.Decrypt("Missing:Name", _charResult);

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}
