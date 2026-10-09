using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.EncryptedConfiguration.Test.TestHelpers;
using Microsoft.Extensions.Configuration;
using Xunit.Abstractions;

namespace HkdfGuard.EncryptedConfiguration.Test;

/// <summary>
/// End to end, from a deployment pipeline encrypting configuration through to the application
/// decrypting it at runtime, with real files in between:
/// <list type="number">
/// <item>Pipeline: random secrets are encrypted with AesGcmPipelineDataProtector, each bound to its
/// own full configuration path (passed as the secret identifier), and written to a nested JSON
/// configuration file alongside some plain settings. The pipeline's key is then wrapped under the
/// deployment's KEK (TestKekWrapper standing in for the native platform wrapper) into a key file.</item>
/// <item>Runtime: KeyRingBuilder unwraps the key file, ConfigurationBuilder.AddJsonFile loads the
/// JSON, and ProtectedConfigurationRoot decrypts every value by its configuration key.</item>
/// </list>
/// Secrets are random per seed; the seeded theories are reproducible, and the unseeded fact logs
/// its seed so any failure can be replayed.
/// </summary>
public sealed class JsonConfigurationEndToEndTests : IDisposable
{
    private const int KeyVersion = 1;

    private static readonly Dictionary<string, string> PlainSettings = new()
    {
        ["Logging:LogLevel:Default"] = "Information",
        ["Logging:LogLevel:Microsoft"] = "Warning",
        ["AllowedHosts"] = "*",
    };

    // Whole graphemes, never split surrogates: ASCII, JSON-escaped characters, whitespace,
    // accented and CJK text, and emoji (surrogate pairs in UTF-16, 4 bytes in UTF-8).
    private static readonly string[] Graphemes =
    [
        .. "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".Select(c => c.ToString()),
        "\"", "\\", "/", "{", "}", "[", "]", ":", ",", "=", ";", "'", "<", ">", "&", "%", "+", " ",
        "\n", "\t", "\r",
        "é", "ü", "ß", "ñ", "Ω", "中", "文", "✓", "€", "🔐", "🚀",
    ];

    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"hkdfguard-e2e-{Guid.NewGuid():N}");
    private readonly ITestOutputHelper _output;
    private readonly List<KeyRing> _rings = [];

    public JsonConfigurationEndToEndTests(ITestOutputHelper output)
    {
        _output = output;
        Directory.CreateDirectory(_directory);
    }

    public void Dispose()
    {
        foreach (var ring in _rings)
            ring.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------- tests

    [Theory]
    [InlineData(1)]
    [InlineData(42)]
    [InlineData(20260601)]
    public async Task EverySecret_EncryptedByThePipeline_DecryptsAtRuntime(int seed)
        => await AssertEverySecretRoundTrips(seed);

    [Fact]
    public async Task EverySecret_EncryptedByThePipeline_DecryptsAtRuntime_RandomSeed()
    {
        var seed = Random.Shared.Next();
        _output.WriteLine($"Seed: {seed} (replay with EverySecret_EncryptedByThePipeline_DecryptsAtRuntime({seed}))");

        await AssertEverySecretRoundTrips(seed);
    }

    [Fact]
    public async Task TheConfigurationFile_HoldsOnlyCiphertextForSecrets()
    {
        var deployment = await RunPipeline(seed: 7, new TestKekWrapper());
        var json = await File.ReadAllTextAsync(deployment.ConfigurationPath);
        var configuration = LoadJson(deployment.ConfigurationPath);

        foreach (var (path, secret) in deployment.Secrets)
        {
            Assert.StartsWith($"enc::v{KeyVersion}::", configuration[path]);
            if (secret.Length >= 12)
                Assert.DoesNotContain(secret, json);
        }
    }

    [Fact]
    public async Task PlainSettings_PassThroughTheProtectedRootUnchanged()
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed: 7, kek);
        var root = await StartApplicationAsync(deployment, kek);

        foreach (var (path, value) in PlainSettings)
            Assert.Equal(value, root[path]);
        Assert.Equal("Information", root.GetSection("Logging:LogLevel")["Default"]);
    }

    [Fact]
    public async Task Lookups_AreCaseInsensitive_LikeConfigurationItself()
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed: 7, kek);
        var root = await StartApplicationAsync(deployment, kek);

        foreach (var (path, secret) in deployment.Secrets)
        {
            Assert.Equal(secret, DecryptChars(root, path.ToUpperInvariant()));
            Assert.Equal(secret, DecryptChars(root, path.ToLowerInvariant()));
        }
    }

    [Fact]
    public async Task ASecretMovedToAnotherKeyInTheFile_FailsAuthentication()
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed: 7, kek);
        var (first, second) = (deployment.Secrets.Keys.First(), deployment.Secrets.Keys.Last());

        // An attacker with write access to the file but no key swaps two encrypted values.
        RewriteJson(deployment.ConfigurationPath, json =>
        {
            var firstValue = GetValue(json, first);
            SetValue(json, first, GetValue(json, second));
            SetValue(json, second, firstValue);
        });
        var root = await StartApplicationAsync(deployment, kek);

        Assert.Throws<AuthenticationTagMismatchException>(() => root.Decrypt(first, new char[8192]));
        Assert.Throws<AuthenticationTagMismatchException>(() => root.Decrypt(second, new char[8192]));
    }

    [Fact]
    public async Task ATamperedCiphertextInTheFile_FailsAuthentication()
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed: 7, kek);
        var target = deployment.Secrets.Keys.First();

        RewriteJson(deployment.ConfigurationPath, json =>
        {
            var value = GetValue(json, target);
            var flipped = value[^4] == 'A' ? 'B' : 'A';
            SetValue(json, target, string.Concat(value.AsSpan(0, value.Length - 4), flipped.ToString(), value.AsSpan(value.Length - 3)));
        });
        var root = await StartApplicationAsync(deployment, kek);

        Assert.ThrowsAny<CryptographicException>(() => root.Decrypt(target, new char[8192]));
    }

    [Fact]
    public async Task TheKeyFile_UnwrapsOnlyUnderTheDeploymentsKek()
    {
        var deployment = await RunPipeline(seed: 7, new TestKekWrapper());

        await Assert.ThrowsAnyAsync<CryptographicException>(() => StartApplicationAsync(deployment, new TestKekWrapper()));
    }

    [Fact]
    public async Task ANewDeploymentsKey_CannotReadThePreviousDeploymentsConfiguration()
    {
        var kek = new TestKekWrapper();
        var previous = await RunPipeline(seed: 7, kek);
        var current = await RunPipeline(seed: 7, kek);

        // Same secrets and the same version number, but each pipeline run generated its own key.
        var root = await StartApplicationAsync(previous with { KeyFilePath = current.KeyFilePath }, kek);

        Assert.Throws<AuthenticationTagMismatchException>(() => root.Decrypt(previous.Secrets.Keys.First(), new char[8192]));
    }

    [Fact]
    public async Task AMissingSecret_DecryptsToNothing_RatherThanThrowing()
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed: 7, kek);
        var root = await StartApplicationAsync(deployment, kek);

        Assert.Equal(0, root.Decrypt("Does:Not:Exist", new char[16]));
        Assert.False(root.TryGetMaxDecryptedLength("Does:Not:Exist", out _));
    }

    [Fact]
    public void APipelineSecretTooLargeForTheFormat_IsRefusedAtEncryptTime()
    {
        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), KeyVersion);

        // ~4 KB of plaintext can't fit in a 4096-character formatted value.
        Assert.Throws<ArgumentException>(() => protector.Encrypt(new string('x', 4000), "Certificates:TooLarge"));
    }

    // ---------------------------------------------------------------- the two stages

    private sealed record Deployment(string ConfigurationPath, string KeyFilePath, IReadOnlyDictionary<string, string> Secrets);

    /// <summary>
    /// The deployment pipeline: encrypt every secret under one fresh key, each bound to its own
    /// configuration path; write the JSON file; wrap the key under the KEK into a key file.
    /// </summary>
    private async Task<Deployment> RunPipeline(int seed, IKeyWrapper kek)
    {
        var secrets = GenerateSecrets(new Random(seed));
        var run = Guid.NewGuid().ToString("N");
        var configurationPath = Path.Combine(_directory, $"appsettings.{run}.json");
        var keyFilePath = Path.Combine(_directory, $"dek.{run}.bin");

        using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), KeyVersion);

        var json = new JsonObject();
        foreach (var (path, value) in PlainSettings)
            SetValue(json, path, value);
        foreach (var (path, secret) in secrets)
            SetValue(json, path, protector.Encrypt(secret, path));
        await File.WriteAllTextAsync(configurationPath, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

        // Hand the key to the wrap step, as the pipeline does with the native platform's wrapper.
        var dek = new byte[32];
        var wrapped = new byte[256];
        try
        {
            Assert.True(Convert.TryFromBase64Chars(protector.GetKeyAsBase64(), dek, out var dekLength));
            Assert.Equal(32, dekLength);
            var wrappedLength = await kek.WrapAsync(dek, wrapped);
            await File.WriteAllBytesAsync(keyFilePath, wrapped[..wrappedLength]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        return new Deployment(configurationPath, keyFilePath, secrets);
    }

    /// <summary>The application at startup: build the KeyRing from the key file and load the JSON.</summary>
    private async Task<ProtectedConfigurationRoot> StartApplicationAsync(Deployment deployment, IKeyWrapper kek)
    {
        var ring = await new KeyRingBuilder()
            .WithKeyWrapper(kek)
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .WithKeyFile(KeyVersion, deployment.KeyFilePath)
            .BuildAsync();
        _rings.Add(ring);

        return new ProtectedConfigurationRoot(LoadJson(deployment.ConfigurationPath), ring);
    }

    private async Task AssertEverySecretRoundTrips(int seed)
    {
        var kek = new TestKekWrapper();
        var deployment = await RunPipeline(seed, kek);
        var root = await StartApplicationAsync(deployment, kek);

        Assert.NotEmpty(deployment.Secrets);
        foreach (var (path, secret) in deployment.Secrets)
        {
            Assert.True(root.TryGetMaxDecryptedLength(path, out var maxLength), $"seed {seed}: {path} not found");

            var chars = new char[maxLength];
            var charsWritten = root.Decrypt(path, chars);
            Assert.True(secret == new string(chars, 0, charsWritten), $"seed {seed}: chars mismatch at {path}");

            var bytes = new byte[maxLength];
            var bytesWritten = root.Decrypt(path, bytes);
            Assert.True(Encoding.UTF8.GetBytes(secret).AsSpan().SequenceEqual(bytes.AsSpan(0, bytesWritten)),
                $"seed {seed}: bytes mismatch at {path}");
        }
    }

    // ---------------------------------------------------------------- secret generation

    /// <summary>
    /// Random secrets at realistic configuration paths: top-level sections, nested sub-sections,
    /// and an array (flattened by configuration to Section:Array:0, :1, ...). Section and leaf
    /// names come from separate namespaces so no path is both a value and a section.
    /// </summary>
    private static Dictionary<string, string> GenerateSecrets(Random random)
    {
        var secrets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var sectionCount = random.Next(2, 5);
        for (var s = 0; s < sectionCount; s++)
        {
            var section = $"Section{s}{RandomName(random)}";
            for (var l = random.Next(1, 5); l > 0; l--)
                secrets[$"{section}:Value{l}{RandomName(random)}"] = RandomSecret(random);

            var sub = $"{section}:Sub{RandomName(random)}";
            for (var l = random.Next(1, 4); l > 0; l--)
                secrets[$"{sub}:Value{l}{RandomName(random)}"] = RandomSecret(random);
        }

        for (var i = 0; i < random.Next(2, 5); i++)
            secrets[$"ApiKeys:Keys:{i}"] = RandomSecret(random);

        secrets["ConnectionStrings:Admin"] = RandomSecret(random);
        secrets["ConnectionStrings:Reporting"] = RandomSecret(random);
        // Formatted values are capped at 4096 characters (about 3 KB of UTF-8): 700 graphemes is at
        // most 2,800 bytes even if every one is a 4-byte emoji.
        secrets["Certificates:Long"] = RandomSecret(random, length: 700);

        return secrets;
    }

    private static string RandomName(Random random)
        => new(Enumerable.Range(0, 6).Select(_ => (char)('a' + random.Next(26))).ToArray());

    private static string RandomSecret(Random random, int? length = null)
    {
        var builder = new StringBuilder();
        for (var i = length ?? random.Next(1, 120); i > 0; i--)
            builder.Append(Graphemes[random.Next(Graphemes.Length)]);
        return builder.ToString();
    }

    // ---------------------------------------------------------------- JSON helpers

    private static IConfigurationRoot LoadJson(string path)
        => new ConfigurationBuilder().AddJsonFile(path, optional: false, reloadOnChange: false).Build();

    private static string DecryptChars(IProtectedReadOnlyCache root, string path)
    {
        var chars = new char[8192];
        var written = root.Decrypt(path, chars);
        return new string(chars, 0, written);
    }

    private static void RewriteJson(string path, Action<JsonObject> edit)
    {
        var json = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        edit(json);
        File.WriteAllText(path, json.ToJsonString());
    }

    // Walks/creates the nested objects (and arrays, for numeric segments) a configuration path names.
    private static void SetValue(JsonObject root, string path, string value)
    {
        var segments = path.Split(':');
        JsonNode node = root;
        for (var i = 0; i < segments.Length; i++)
        {
            var isLast = i == segments.Length - 1;
            var nextIsIndex = !isLast && int.TryParse(segments[i + 1], out _);
            JsonNode Create() => isLast ? JsonValue.Create(value)! : nextIsIndex ? new JsonArray() : new JsonObject();

            if (node is JsonArray array)
            {
                var index = int.Parse(segments[i]);
                if (index == array.Count)
                    array.Add(Create());
                else if (isLast)
                    array[index] = Create();
                node = array[index]!;
            }
            else
            {
                var obj = node.AsObject();
                if (isLast || obj[segments[i]] is null)
                    obj[segments[i]] = Create();
                node = obj[segments[i]]!;
            }
        }
    }

    private static string GetValue(JsonObject root, string path)
    {
        JsonNode node = root;
        foreach (var segment in path.Split(':'))
            node = node is JsonArray array ? array[int.Parse(segment)]! : node[segment]!;
        return node.GetValue<string>();
    }
}
