using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// What a key costs to bring up and tear down, apart from the key wrapper itself (a fixed,
/// in-memory one here; NativeKeyWrapperBenchmarks measures the real unwrap): revealing into a
/// pinned buffer, building the session's first AesGcm, looking up the process-wide encryption
/// budget for the key, starting and then stopping the background refresh loop, and zeroing
/// everything on dispose. Paid at startup per key file, and again on every ephemeral key rotation.
/// BuildRing goes through KeyRingBuilder with one ephemeral key - the whole startup path an
/// application with no key file takes.
/// </summary>
[MemoryDiagnoser]
public class CryptoProviderLifecycleBenchmarks
{
    private FixedKeyWrapper _wrapper = null!;
    private AesGcmCryptoProviderFactory _factory = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _wrapper = new FixedKeyWrapper(RandomNumberGenerator.GetBytes(32));
        _factory = new AesGcmCryptoProviderFactory();
    }

    [Benchmark]
    public async Task CreateAndDispose()
    {
        var provider = await AesGcmCryptoProvider.CreateAsync(_wrapper, [.. "wrapped"u8], BenchmarkKeys.RefreshSeconds);
        await provider.DisposeAsync();
    }

    [Benchmark]
    public async Task CreateEphemeralAndDispose()
    {
        var provider = await _factory.CreateEphemeralAsync(_wrapper, BenchmarkKeys.RefreshSeconds);
        await provider.DisposeAsync();
    }

    [Benchmark]
    public async Task BuildRingAndDispose()
    {
        var ring = await new KeyRingBuilder()
            .WithServiceName("com.hkdfguard.benchmark")
            .WithKeyWrapper(_wrapper)
            .WithCryptoProviderFactory(_factory)
            .WithFormatProvider(new DefaultFormatProvider())
            .WithKeyRefreshInterval(BenchmarkKeys.RefreshSeconds)
            .WithEphemeralKey(1)
            .WithoutEphemeralKeyRotation()
            .BuildAsync();
        await ring.DisposeAsync();
    }
}
