using System.Text;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.Pipeline;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// SecretPipelineWriter's own work in a release pipeline, against an in-memory store: pulling
/// every secret (validating it as UTF-8, transcoding, encrypting each whole value and each JSON key
/// requested) and writing them all as one JSON secrets file. The cloud writers add only their
/// store's round trips. SecretCount covers a small service and a large one; half the requests are
/// a key of a JSON secret ("name#key"), half a whole secret.
/// </summary>
[MemoryDiagnoser]
public class SecretPipelineWriterBenchmarks
{
    [Params(10, 100)]
    public int SecretCount { get; set; }

    private AesGcmPipelineDataProtector _protector = null!;
    private InMemoryPipelineWriter _writer = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 1);
        var store = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var names = new List<string>();
        for (var i = 0; i < SecretCount; i++)
        {
            if (i % 2 == 0)
            {
                store[$"plain-{i}"] = Encoding.UTF8.GetBytes($"value-{i}-{new string('x', 24)}");
                names.Add($"plain-{i}");
            }
            else
            {
                store[$"json-{i}"] = Encoding.UTF8.GetBytes($"{{\"username\":\"app-{i}\",\"password\":\"{new string('p', 24)}\"}}");
                names.Add($"json-{i}#password");
            }
        }

        _writer = new InMemoryPipelineWriter(_protector, names, store);
    }

    [Benchmark]
    public Task PullSecrets() => _writer.PullSecretsAsync();

    [Benchmark]
    public async Task<long> PullAndWriteJsonSecrets()
    {
        await _writer.PullSecretsAsync();
        using var destination = new MemoryStream();
        await _writer.WriteJsonSecretsAsync(destination);
        return destination.Length;
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _writer.Dispose();
        _protector.Dispose();
    }

    private sealed class InMemoryPipelineWriter(IPipelineDataProtector protector, IList<string> names, Dictionary<string, byte[]> store)
        : SecretPipelineWriter(protector, names, static name => name.Length > 0)
    {
        protected override Task ReadSecretAsync(string name, IReadOnlyList<SecretRequest> requests, IDictionary<string, string> values,
            CancellationToken cancellationToken)
        {
            if (store.TryGetValue(name, out var secret))
                ProtectSecret(secret, requests, values);
            return Task.CompletedTask;
        }
    }
}
