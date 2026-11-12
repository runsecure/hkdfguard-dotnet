using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.CryptoProvider.AesGcm256;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// AesGcmCryptoProvider under contention. Each session keeps a pool (a ConcurrentStack) of AesGcm
/// instances, one per concurrent operation, plus a shared Interlocked encryption budget; a single
/// threaded benchmark never exercises either past one instance. A fixed total of operations is
/// split across Threads parallel workers each invocation, so the reported time is per operation:
/// flat as Threads rises means the pool scales; rising means contention on the pool or the budget
/// counter. A small (64-byte) payload keeps the cipher itself from hiding that overhead.
/// </summary>
[MemoryDiagnoser]
public class CryptoProviderConcurrencyBenchmarks
{
    private const int TotalOperations = 8192;
    private const int PayloadSize = 64;
    private const int Overhead = 28;

    [Params(1, 2, 4, 8)]
    public int Threads { get; set; }

    private AesGcmCryptoProvider _provider = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _provider = await BenchmarkKeys.CreateProviderAsync();
        _plaintext = RandomNumberGenerator.GetBytes(PayloadSize);
        _ciphertext = new byte[PayloadSize + Overhead];
        _provider.Encrypt((byte[])_plaintext.Clone(), _ciphertext);
    }

    [Benchmark(OperationsPerInvoke = TotalOperations)]
    public void ParallelEncrypt()
        => Parallel.For(0, Threads, new ParallelOptions { MaxDegreeOfParallelism = Threads }, _ =>
        {
            var scratch = new byte[PayloadSize];
            var result = new byte[PayloadSize + Overhead];
            for (var i = 0; i < TotalOperations / Threads; i++)
            {
                _plaintext.CopyTo(scratch, 0);
                _provider.Encrypt(scratch, result);
            }
        });

    [Benchmark(OperationsPerInvoke = TotalOperations)]
    public void ParallelDecrypt()
        => Parallel.For(0, Threads, new ParallelOptions { MaxDegreeOfParallelism = Threads }, _ =>
        {
            var result = new byte[PayloadSize];
            for (var i = 0; i < TotalOperations / Threads; i++)
                _provider.Decrypt(_ciphertext, result);
        });

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _provider.DisposeAsync();
}
