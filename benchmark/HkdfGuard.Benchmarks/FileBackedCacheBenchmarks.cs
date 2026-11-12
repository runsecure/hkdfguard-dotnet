using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Benchmarks.Infrastructure;
using HkdfGuard.Cache;
using HkdfGuard.Cache.JsonSecretsFile;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.SecureFile.Test.TestHelpers;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// The two caches over files a deployment pipeline wrote - FilePerSecretCache (a file per secret)
/// and JsonSecretsFileReadOnlyCache (one JSON object of them) - in a folder the current account is
/// trusted for, as the cache tests set it up. Every value is written by AesGcmPipelineDataProtector,
/// as SecretPipelineWriter writes them, and read through a ring holding the same key.
/// <para>
/// Cold* builds a new cache and makes its first lookup: the trusted-path checks (ownership and
/// ACLs of the file and every folder above it), the read, the parse and the decrypt - what each
/// secret costs at startup. A JSON secrets file is loaded, and every value authenticated, as one,
/// so its cold cost grows with SecretCount however few are looked up. Warm* is every later lookup,
/// answered from memory. FilePerSecretCacheMiss is a name with no file: a miss isn't remembered, so
/// every lookup of it goes back to the filesystem - which a ProtectedCacheCollection pays on every
/// name a later source answers, when this cache is ahead of it.
/// </para>
/// </summary>
[MemoryDiagnoser]
public class FileBackedCacheBenchmarks
{
    [Params(10, 100)]
    public int SecretCount { get; set; }

    private TrustedTempDirectory _directory = null!;
    private KeyRing _ring = null!;
    private DefaultFormatProvider _format = null!;
    private string _jsonPath = null!;
    private FilePerSecretCache _warmFiles = null!;
    private JsonSecretsFileReadOnlyCache _warmJson = null!;
    private char[] _result = null!;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        _directory = new TrustedTempDirectory();
        _format = new DefaultFormatProvider();

        using var pipeline = new AesGcmPipelineDataProtector(_format, 1);
        var key = Convert.FromBase64String(pipeline.GetKeyAsBase64().ToString());
        _ring = await BenchmarkKeys.CreateRingAsync(key, _format);

        var filesFolder = FilesFolder = Path.Combine(_directory.Path, "files");
        Directory.CreateDirectory(filesFolder);
        var json = new Dictionary<string, string>();
        for (var i = 0; i < SecretCount; i++)
        {
            var name = $"secret-{i}";
            var encrypted = pipeline.Encrypt(BenchmarkKeys.Text(32), name);
            // No byte-order mark: the cache reads the file as the bare formatted value.
            File.WriteAllBytes(Path.Combine(filesFolder, name), Encoding.UTF8.GetBytes(encrypted));
            json[name] = encrypted;
        }

        _jsonPath = _directory.Write("secrets.json", JsonSerializer.Serialize(json));

        _result = new char[64];
        _warmFiles = new FilePerSecretCache(filesFolder, _directory.Trust, _ring, _format);
        _warmJson = new JsonSecretsFileReadOnlyCache(_jsonPath, _directory.Trust, _ring, _format);
        if (_warmFiles.Decrypt("secret-0", _result) == 0 || _warmJson.Decrypt("secret-0", _result) == 0)
            throw new InvalidOperationException("The benchmark's secrets didn't load.");
    }

    private string FilesFolder { get; set; } = null!;

    [Benchmark]
    public int FilePerSecretCacheCold()
        => new FilePerSecretCache(FilesFolder, _directory.Trust, _ring, _format).Decrypt("secret-0", _result);

    [Benchmark]
    public int FilePerSecretCacheWarm() => _warmFiles.Decrypt("secret-0", _result);

    [Benchmark]
    public int FilePerSecretCacheMiss() => _warmFiles.Decrypt("no-such-secret", _result);

    [Benchmark]
    public int JsonSecretsFileCold()
        => new JsonSecretsFileReadOnlyCache(_jsonPath, _directory.Trust, _ring, _format).Decrypt("secret-0", _result);

    [Benchmark]
    public int JsonSecretsFileWarm() => _warmJson.Decrypt("secret-0", _result);

    [Benchmark]
    public int JsonSecretsFileMiss() => _warmJson.Decrypt("no-such-secret", _result);

    [GlobalCleanup]
    public async Task GlobalCleanup()
    {
        await _ring.DisposeAsync();
        _directory.Dispose();
    }
}
