using BenchmarkDotNet.Attributes;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Benchmarks.Infrastructure;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// AesGcmPipelineDataProtector - the deployment pipeline's protector, holding its key directly
/// rather than through a key wrapper. Encrypt runs once per secret per release, binding each value
/// to its identifier (a fresh AAD array per call); Decrypt is what a verification step would run.
/// Text lengths straddle ArrayUtility.MaxStackBytes (4096) as DataProtectorBenchmarks' do.
/// </summary>
[MemoryDiagnoser]
public class PipelineDataProtectorBenchmarks
{
    private const string SecretIdentifier = "ConnectionStrings:Primary";

    [Params(32, 2048, 8192)]
    public int TextLength { get; set; }

    private AesGcmPipelineDataProtector _protector = null!;
    private string _plaintext = null!;
    private string _encrypted = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(1 << 20), 1);
        _plaintext = BenchmarkKeys.Text(TextLength);
        _encrypted = _protector.Encrypt(_plaintext, SecretIdentifier);
        _result = new char[_protector.GetMaxDecryptedLength(_encrypted)];
    }

    [Benchmark]
    public string Encrypt() => _protector.Encrypt(_plaintext, SecretIdentifier);

    [Benchmark]
    public int Decrypt() => _protector.Decrypt(_encrypted, SecretIdentifier, _result);

    [GlobalCleanup]
    public void GlobalCleanup() => _protector.Dispose();
}
