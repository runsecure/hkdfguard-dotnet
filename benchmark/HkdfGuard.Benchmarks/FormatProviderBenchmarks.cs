using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// DefaultFormatProvider alone - the "ENC:v&lt;version&gt;:&lt;base64&gt;" envelope every protector
/// and file-backed cache writes and parses, with no cryptography. Format builds the base64 and the
/// final string; Parse validates the segments and the base64, then decodes into a new array;
/// GetMaxDecryptedLength is what callers run first to size their result buffer, so it is paid
/// on every lookup too. Sizes are ciphertext lengths: a 64-byte secret (+28 bytes nonce and tag)
/// and a 4 KiB blob.
/// </summary>
[MemoryDiagnoser]
public class FormatProviderBenchmarks
{
    [Params(92, 4124)]
    public int CiphertextLength { get; set; }

    private DefaultFormatProvider _format = null!;
    private KeyTrackingValue _value = null!;
    private string _formatted = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _format = new DefaultFormatProvider(1 << 20);
        _value = new KeyTrackingValue { KeyVersion = 7, Value = RandomNumberGenerator.GetBytes(CiphertextLength) };
        _formatted = _format.Format(_value);
    }

    [Benchmark]
    public string Format() => _format.Format(_value);

    [Benchmark]
    public KeyTrackingValue Parse() => _format.Parse(_formatted);

    [Benchmark]
    public int GetMaxDecryptedLength() => _format.GetMaxDecryptedLength(_formatted);
}
