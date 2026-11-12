using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.Infrastructure;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks AesGcmCryptoSession.Encrypt/Decrypt (via AesGcmCryptoProvider, since the session type
/// itself is internal to HkdfGuard.CryptoProvider.AesGcm256) - the raw symmetric-cipher cost
/// underlying every higher-level operation in this library, isolated from key derivation and
/// storage. The key is bound once at construction, so unlike Encrypt's plaintext argument (zeroed
/// as a side effect once it's done with it, refreshed from a pristine template before every
/// invocation here), there's no per-call key to restore. The provider also returns the same cached
/// session across every call here (a 300-second refresh interval outlives any single benchmark
/// run), so this measures Encrypt/Decrypt themselves, not session refresh. PayloadSize is
/// parameterized across a small secret (64 bytes), a typical config blob (4 KiB), and a larger
/// payload (1 MiB) to show how per-call overhead versus per-byte throughput trade off. The *WithAad
/// variants take the overload every cache and protector actually calls - with a ~40-byte
/// name-binding AAD - so the AAD's GHASH cost shows against the plain one.
/// </summary>
[MemoryDiagnoser]
public class AesGcmCryptoSessionBenchmarks
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    [Params(64, 4096, 1_048_576)]
    public int PayloadSize { get; set; }

    private ICryptoProvider _provider = null!;
    private byte[] _plaintextTemplate = null!;
    private byte[] _plaintextScratch = null!;
    private byte[] _encryptResult = null!;
    private byte[] _ciphertext = null!;
    private byte[] _ciphertextWithAad = null!;
    private byte[] _decryptResult = null!;
    private byte[] _aad = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _provider = await BenchmarkKeys.CreateProviderAsync();
        _plaintextTemplate = RandomNumberGenerator.GetBytes(PayloadSize);
        _plaintextScratch = new byte[PayloadSize];
        _encryptResult = new byte[PayloadSize + NonceSize + TagSize];
        _decryptResult = new byte[PayloadSize];
        // The shape ProtectedCacheBase binds an entry to: its prefix plus the upper-cased name.
        _aad = ProtectedCacheBase.AadFor("ConnectionStrings:Primary");

        // Precompute ciphertexts to decrypt repeatedly - Decrypt doesn't zero its ciphertext
        // argument, so these buffers are safe to reuse across every Decrypt invocation.
        _ciphertext = new byte[PayloadSize + NonceSize + TagSize];
        _provider.Encrypt((byte[])_plaintextTemplate.Clone(), _ciphertext);
        _ciphertextWithAad = new byte[PayloadSize + NonceSize + TagSize];
        _provider.Encrypt((byte[])_plaintextTemplate.Clone(), _aad, _ciphertextWithAad);
    }

    [Benchmark]
    public int Encrypt()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _provider.Encrypt(_plaintextScratch, _encryptResult);
    }

    [Benchmark]
    public int Decrypt()
        => _provider.Decrypt(_ciphertext, _decryptResult);

    [Benchmark]
    public int EncryptWithAad()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _provider.Encrypt(_plaintextScratch, _aad, _encryptResult);
    }

    [Benchmark]
    public int DecryptWithAad()
        => _provider.Decrypt(_ciphertextWithAad, _aad, _decryptResult);

    [GlobalCleanup]
    public async Task GlobalCleanup()
    {
        await _provider.DisposeAsync();
    }
}
