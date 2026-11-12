using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.V1;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// NativeHkdfKeyWrapperV1 against the installed native library and a provisioned KEK - the real
/// cost every other benchmark stubs out with FixedKeyWrapper. Unwrap is paid at startup per key
/// file and again by every AesGcmCryptoProvider on every refresh interval; GenerateAndWrap per
/// ephemeral key (startup and each rotation); Wrap by the release pipeline, once per release.
/// <para>
/// Needs the native library installed and a KEK provisioned for the service named by the
/// HKDFGUARD_TEST_SERVICE environment variable, or else the integration-test service
/// com.hkdfguard.integration.test.221 (scripts/provision-windows-test-key.ps1 on Windows,
/// scripts/provision-linux-test-key.sh on Linux). Without them setup fails and BenchmarkDotNet
/// reports this class's benchmarks as failed; the rest are unaffected. Run it on its own with
/// --filter *NativeKeyWrapper*.
/// </para>
/// </summary>
[MemoryDiagnoser]
public class NativeKeyWrapperBenchmarks
{
    private const string DefaultServiceName = "com.hkdfguard.integration.test.221";

    private NativeHkdfKeyWrapperV1 _wrapper = null!;
    private byte[] _dek = null!;
    private byte[] _wrapped = null!;
    private byte[] _wrapResult = null!;
    private byte[] _unwrapResult = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        var service = Environment.GetEnvironmentVariable("HKDFGUARD_TEST_SERVICE") is { Length: > 0 } configured
            ? configured
            : DefaultServiceName;
        _wrapper = new NativeHkdfKeyWrapperV1(service);
        _dek = RandomNumberGenerator.GetBytes(32);
        _wrapResult = new byte[WrappedKeyLimits.MaxBytes];
        _unwrapResult = new byte[32];

        var length = await _wrapper.WrapAsync(_dek, _wrapResult);
        _wrapped = _wrapResult[..length];
    }

    [Benchmark]
    public ValueTask<int> Unwrap() => _wrapper.UnwrapAsync(_wrapped, _unwrapResult);

    [Benchmark]
    public ValueTask<int> Wrap() => _wrapper.WrapAsync(_dek, _wrapResult);

    [Benchmark]
    public ValueTask<int> GenerateAndWrap() => _wrapper.GenerateAndWrapAsync(_wrapResult);

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        CryptographicOperations.ZeroMemory(_dek);
        CryptographicOperations.ZeroMemory(_unwrapResult);
    }
}
