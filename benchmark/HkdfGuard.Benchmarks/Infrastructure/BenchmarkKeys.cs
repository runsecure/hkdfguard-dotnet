using System.Diagnostics;
using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using Dek = HkdfGuard.DataEncryptionKey.DataEncryptionKey;

namespace HkdfGuard.Benchmarks.Infrastructure;

/// <summary>
/// Reveals the same fixed key regardless of the wrapped bytes passed in - isolates a benchmark from
/// real key-wrapping cost (see NativeKeyWrapperBenchmarks for that), which a provider only pays at
/// creation and once per refresh interval anyway.
/// </summary>
internal sealed class FixedKeyWrapper(byte[] key) : IKeyWrapper
{
    // Benchmark-only: a plain read. Real key wrappers must refuse a key file another account could have replaced.
    public async ValueTask<byte[]> ReadKeyFileAsync(string path, CancellationToken cancellationToken = default)
        => await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);

    public ValueTask<int> WrapAsync(ReadOnlyMemory<byte> plaintext, Memory<byte> result, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public ValueTask<int> UnwrapAsync(ReadOnlyMemory<byte> wrapped, Memory<byte> result, CancellationToken cancellationToken = default)
    {
        key.CopyTo(result.Span);
        return ValueTask.FromResult(key.Length);
    }

    // Stands in for "generate a DEK and wrap it": the "wrapped" bytes are never interpreted, since
    // UnwrapAsync always reveals the fixed key.
    public ValueTask<int> GenerateAndWrapAsync(Memory<byte> result, CancellationToken cancellationToken = default)
    {
        "wrapped"u8.CopyTo(result.Span);
        return ValueTask.FromResult(7);
    }
}

/// <summary>Builds the real provider / DEK / key ring stack every higher-level benchmark runs on.</summary>
internal static class BenchmarkKeys
{
    // The longest a provider allows: no refresh lands inside a benchmark run's iterations.
    public const int RefreshSeconds = 300;

    public static Task<AesGcmCryptoProvider> CreateProviderAsync(byte[]? key = null)
        => AesGcmCryptoProvider.CreateAsync(new FixedKeyWrapper(key ?? RandomNumberGenerator.GetBytes(32)), [.. "wrapped"u8], RefreshSeconds);

    public static async Task<Dek> CreateDekAsync(byte[]? key = null, EncryptionDeadline? deadline = null)
        => new(await CreateProviderAsync(key), deadline);

    /// <summary>A ring holding one key, at version 1, the current version.</summary>
    /// <param name="formatProvider">Defaults to a DefaultFormatProvider allowing values up to 1 MiB,
    /// so payload sizes above the default 4096-character limit can be measured.</param>
    public static async Task<KeyRing> CreateRingAsync(byte[]? key = null, IEncryptedFormatProvider? formatProvider = null)
    {
        var ring = new KeyRing(formatProvider ?? LargeFormat());
        ring.Add(1, await CreateDekAsync(key));
        return ring;
    }

    public static DefaultFormatProvider LargeFormat() => new(1 << 20);

    /// <summary>Text of exactly <paramref name="length"/> ASCII characters (so as many UTF-8 bytes).</summary>
    public static string Text(int length)
        => string.Create(length, 0, static (span, _) =>
        {
            for (var i = 0; i < span.Length; i++)
                span[i] = (char)('a' + i % 26);
        });
}

/// <summary>
/// An ActivityListener recording every activity from HkdfGuard's sources, as an application
/// exporting traces (OpenTelemetry etc.) would - without one, StartActivity returns null and the
/// telemetry paths cost almost nothing, which is what every other benchmark measures.
/// </summary>
internal sealed class HkdfGuardActivityListener : IDisposable
{
    private readonly ActivityListener _listener = new()
    {
        ShouldListenTo = source => source.Name.StartsWith("HkdfGuard", StringComparison.Ordinal),
        Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
    };

    public HkdfGuardActivityListener() => ActivitySource.AddActivityListener(_listener);

    public void Dispose() => _listener.Dispose();
}
