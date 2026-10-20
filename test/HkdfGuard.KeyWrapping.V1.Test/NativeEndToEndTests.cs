using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Cache;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.FormatProvider;
using HkdfGuard.EncryptedConfiguration;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;
using Microsoft.Extensions.Configuration;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// End to end over the real native KEK: the paths a deployment and a running application actually
/// take, from a pipeline encrypting configuration through to the application reading it back, and
/// the runtime keys a process generates for itself. Runs against the provisioned test service (see
/// NativeTestEnvironment) and is reported as skipped where there is none - on Windows, run
/// scripts/provision-windows-test-key.ps1 once from an elevated PowerShell.
/// </summary>
public sealed class NativeEndToEndTests : IDisposable
{
    private const int KeyFileVersion = 3;

    // Created on first use: only the tests that write a key file need it, and on Linux that is a
    // private folder the native library trusts (NeedsKeyFileDirectory), never /tmp.
    private string? _directory;

    private string KeyFileDirectory => _directory ??= TestDirectories.CreateKeyFileDirectory("hkdfguard-e2e-");

    private static string Service => NativeTestEnvironment.ProvisionedService;

    public void Dispose()
    {
        if (_directory is not null)
            Directory.Delete(_directory, recursive: true);
    }

    private static KeyRingBuilder RingBuilder(string service) => new KeyRingBuilder()
        .WithServiceName(service)
        .WithKeyWrapper(new NativeHkdfKeyWrapperV1(service))
        .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
        .WithKeyRefreshInterval(60);

    // What the release pipeline does: protect configuration under a fresh in-memory key, then
    // hand that key to the native KEK and write the wrapped result as the release's key file.
    private async Task<(string KeyFilePath, Dictionary<string, string?> Configuration)> RunPipelineAsync(
        params (string Key, string Secret)[] secrets)
    {
        using var pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), KeyFileVersion);
        var configuration = secrets.ToDictionary(s => s.Key, s => (string?)pipeline.Encrypt(s.Secret, s.Key));

        var dek = ArrayUtility.AllocatePinned<byte>(32);
        try
        {
            Assert.True(Convert.TryFromBase64Chars(pipeline.GetKeyAsBase64(), dek, out var written));
            Assert.Equal(32, written);

            var wrapped = new byte[WrappedKeyLimits.MaxBytes];
            var wrappedLength = await new NativeHkdfKeyWrapperV1(Service).WrapAsync(dek, wrapped);

            var path = Path.Combine(KeyFileDirectory, $"wrapped-dek-v{KeyFileVersion}.bin");
            await TestDirectories.WriteKeyFileAsync(path, wrapped.AsMemory(0, wrappedLength));
            return (path, configuration);
        }
        finally
        {
            ArrayUtility.ZeroMemory(dek);
        }
    }

    private static string Reveal(IProtectedReadOnlyCache source, string name)
    {
        Assert.True(source.TryGetMaxDecryptedLength(name, out var max));
        var result = new char[max];
        return new string(result, 0, source.Decrypt(name, result.AsSpan()));
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task ADeployment_PipelineEncryptedConfiguration_DecryptsThroughItsNativelyWrappedKeyFile()
    {
        var (keyFile, values) = await RunPipelineAsync(
            ("ConnectionStrings:Admin", "Server=db;User=admin;Password=s3cret"),
            ("Api:Key", "k-0123456789abcdef"));

        await using var ring = await RingBuilder(Service).WithKeyFile(KeyFileVersion, keyFile).BuildAsync();
        var root = new ProtectedConfigurationRoot(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), ring);

        Assert.Equal("Server=db;User=admin;Password=s3cret", Reveal(root, "ConnectionStrings:Admin"));
        Assert.Equal("k-0123456789abcdef", Reveal(root, "Api:Key"));
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task ADeployment_ValuesMovedToAnotherKey_FailAuthentication()
    {
        var (keyFile, values) = await RunPipelineAsync(("ConnectionStrings:Admin", "admin-only"), ("ConnectionStrings:Reports", "reports"));
        values["ConnectionStrings:Reports"] = values["ConnectionStrings:Admin"]; // an edited configuration file

        await using var ring = await RingBuilder(Service).WithKeyFile(KeyFileVersion, keyFile).BuildAsync();
        var root = new ProtectedConfigurationRoot(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), ring);

        Assert.Throws<AuthenticationTagMismatchException>(() => Reveal(root, "ConnectionStrings:Reports"));
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task ARestart_ReadingTheSameKeyFile_RevealsTheSameKey()
    {
        var (keyFile, values) = await RunPipelineAsync(("Secret", "survives a restart"));
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        await using (var first = await RingBuilder(Service).WithKeyFile(KeyFileVersion, keyFile).BuildAsync())
            Assert.Equal("survives a restart", Reveal(new ProtectedConfigurationRoot(configuration, first), "Secret"));

        await using var second = await RingBuilder(Service).WithKeyFile(KeyFileVersion, keyFile).BuildAsync();
        Assert.Equal("survives a restart", Reveal(new ProtectedConfigurationRoot(configuration, second), "Secret"));
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task AKeyFile_WrappedUnderAnotherService_RefusesToBuild()
    {
        var (keyFile, _) = await RunPipelineAsync(("Secret", "value"));

        await Assert.ThrowsAsync<CryptographicException>(() =>
            RingBuilder(NativeTestEnvironment.OtherServiceName).WithKeyFile(KeyFileVersion, keyFile).BuildAsync());
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task ATamperedKeyFile_RefusesToBuild()
    {
        // The last byte is part of the AEAD tag, which no platform's library can check without the
        // KEK, so the file reads back fine and the build fails at unwrap. (A change to the payload's
        // structure is refused earlier, when the file is read - see LinuxNativeIntegrationTests.)
        var (keyFile, _) = await RunPipelineAsync(("Secret", "value"));
        var bytes = await File.ReadAllBytesAsync(keyFile);
        bytes[^1] ^= 0x01;
        await TestDirectories.WriteKeyFileAsync(keyFile, bytes);

        await Assert.ThrowsAsync<CryptographicException>(() =>
            RingBuilder(Service).WithKeyFile(KeyFileVersion, keyFile).BuildAsync());
    }

    [NativeIntegrationFact]
    public async Task RuntimeKeys_GeneratedThroughTheNativeKek_ProtectValuesAndTheCache()
    {
        await using var ring = await RingBuilder(Service).WithEphemeralKey(100).BuildAsync();

        var protector = ring.CreateProtector("session");
        var formatted = protector.Encrypt("runtime value");
        Assert.StartsWith("enc::v100::", formatted);
        var result = new char[protector.GetMaxDecryptedLength(formatted)];
        Assert.Equal("runtime value", new string(result, 0, protector.Decrypt(formatted, result)));

        var cache = new ProtectedCache(ring);
        cache.Add("token", "cached secret".ToCharArray());
        Assert.Equal("cached secret", Reveal(cache, "token"));
    }

    [NativeIntegrationFact(NeedsKeyFileDirectory = true)]
    public async Task ADeployedAndARuntimeKey_TogetherInOneRing_EachDoTheirJob()
    {
        var (keyFile, values) = await RunPipelineAsync(("Secret", "from the release"));

        await using var ring = await RingBuilder(Service)
            .WithKeyFile(KeyFileVersion, keyFile)
            .WithEphemeralKey(100)
            .BuildAsync();

        // Configuration decrypts under the release's key file; new values encrypt under the runtime key.
        Assert.Equal("from the release", Reveal(new ProtectedConfigurationRoot(new ConfigurationBuilder().AddInMemoryCollection(values).Build(), ring), "Secret"));
        Assert.Equal(100, ring.CurrentVersion);
        Assert.StartsWith("enc::v100::", ring.CreateProtector("new").Encrypt("value"));
    }

    [NativeIntegrationFact]
    public async Task BackgroundRefresh_AgainstTheRealKek_KeepsTheKeyInService()
    {
        await using var ring = await RingBuilder(Service).WithKeyRefreshInterval(1).WithEphemeralKey(1).BuildAsync();
        var protector = ring.CreateProtector("refresh");
        var before = protector.Encrypt("written before the refreshes");

        await Task.Delay(TimeSpan.FromSeconds(2.5)); // two background re-reveals through the native KEK

        var result = new char[64];
        Assert.Equal("written before the refreshes", new string(result, 0, protector.Decrypt(before, result)));
        var after = protector.Encrypt("written after");
        Assert.Equal("written after", new string(result, 0, protector.Decrypt(after, result)));
    }
}
