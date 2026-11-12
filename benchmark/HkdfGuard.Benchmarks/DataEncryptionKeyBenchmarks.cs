using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.DataEncryptionKey;
using Dek = HkdfGuard.DataEncryptionKey.DataEncryptionKey;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// DataEncryptionKey, the IDataEncryptionKey every cache and protector encrypts through: on top of
/// the provider (AesGcmCryptoSessionBenchmarks) it allocates the ciphertext array on each Encrypt
/// and checks the key's deadline against the clock. *WithDeadline uses a key carrying a deadline
/// far in the future - as every key-file key does (KeyRingBuilder's key-file age limit) - so the
/// clock read and comparisons show against an ephemeral key, which has none. Sizes are a small
/// secret and a 4 KiB blob; past that the cipher dominates, as AesGcmCryptoSessionBenchmarks shows.
/// </summary>
[MemoryDiagnoser]
public class DataEncryptionKeyBenchmarks
{
    [Params(64, 4096)]
    public int PayloadSize { get; set; }

    private Dek _key = null!;
    private Dek _keyWithDeadline = null!;
    private byte[] _aad = null!;
    private byte[] _plaintextTemplate = null!;
    private byte[] _plaintextScratch = null!;
    private byte[] _ciphertext = null!;
    private byte[] _decryptResult = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        var keyBytes = RandomNumberGenerator.GetBytes(32);
        _key = await BenchmarkKeys.CreateDekAsync((byte[])keyBytes.Clone());
        var now = DateTimeOffset.UtcNow;
        _keyWithDeadline = await BenchmarkKeys.CreateDekAsync((byte[])keyBytes.Clone(), new EncryptionDeadline
        {
            WarnAt = now.AddYears(1),
            RefuseAt = now.AddYears(2),
            Reason = "benchmark",
        });

        _aad = ProtectedCacheBase.AadFor("ConnectionStrings:Primary");
        _plaintextTemplate = RandomNumberGenerator.GetBytes(PayloadSize);
        _plaintextScratch = new byte[PayloadSize];
        _ciphertext = _key.Encrypt((byte[])_plaintextTemplate.Clone(), _aad);
        _decryptResult = new byte[PayloadSize];
    }

    [Benchmark]
    public byte[] Encrypt()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _key.Encrypt(_plaintextScratch, _aad);
    }

    [Benchmark]
    public byte[] EncryptWithDeadline()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _keyWithDeadline.Encrypt(_plaintextScratch, _aad);
    }

    [Benchmark]
    public int Decrypt()
        => _key.Decrypt(_ciphertext, _aad, _decryptResult);

    [GlobalCleanup]
    public async Task GlobalCleanup()
    {
        await _key.DisposeAsync();
        await _keyWithDeadline.DisposeAsync();
    }
}
