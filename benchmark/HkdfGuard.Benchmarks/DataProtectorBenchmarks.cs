using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// KeyRing.CreateProtector's IDataProtector: string in, formatted "ENC:v1:base64" string out, and
/// back - UTF-8 transcoding, the key ring lookup, the DEK, then the format provider's base64. Text
/// lengths straddle ArrayUtility.MaxStackBytes (4096): at or under it the plaintext bytes are
/// stackalloc'd, over it they're a pinned array, so 8192 shows that switch. CreateProtector is
/// measured on its own because ProtectedConfigurationRoot creates one on every lookup.
/// </summary>
[MemoryDiagnoser]
public class DataProtectorBenchmarks
{
    [Params(32, 2048, 8192)]
    public int TextLength { get; set; }

    private KeyRing _ring = null!;
    private IDataProtector _protector = null!;
    private string _plaintext = null!;
    private string _encrypted = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _ring = await BenchmarkKeys.CreateRingAsync();
        _protector = _ring.CreateProtector(ProtectedConfigurationPurpose.For("ConnectionStrings:Primary"));
        _plaintext = BenchmarkKeys.Text(TextLength);
        _encrypted = _protector.Encrypt(_plaintext);
        _result = new char[_protector.GetMaxDecryptedLength(_encrypted)];
    }

    [Benchmark]
    public string Encrypt() => _protector.Encrypt(_plaintext);

    [Benchmark]
    public int Decrypt() => _protector.Decrypt(_encrypted, _result);

    [Benchmark]
    public int GetMaxDecryptedLength() => _protector.GetMaxDecryptedLength(_encrypted);

    [Benchmark]
    public IDataProtector CreateProtector() => _ring.CreateProtector(ProtectedConfigurationPurpose.For("ConnectionStrings:Primary"));

    [GlobalCleanup]
    public async Task GlobalCleanup() => await _ring.DisposeAsync();
}
