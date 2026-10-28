using System.Security.Cryptography.X509Certificates;
using HkdfGuard.Cache.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Cache.HashiCorpVault.Test;

/// <summary>
/// Real reads of a secret the caller provides, in a KV version 2 engine mounted at "secret" (a dev
/// server's default), with a token the caller provides:
/// <code>
/// vault kv put secret/hkdfguard/test value=s3cret
/// HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
/// HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \
/// dotnet test test/HkdfGuard.Cache.HashiCorpVault.Test
/// </code>
/// Without HKDFGUARD_TEST_VAULT_SECRET_NAME every test here is reported as skipped - never as passed.
/// HKDFGUARD_TEST_VAULT_CACERT is needed only for a server certificate the operating system doesn't
/// trust. The token needs only read on that secret's path; the tests never list, write or delete.
/// </summary>
public class HashiCorpVaultSecretCacheIntegrationTests
{
    public const string SecretNameVariable = "HKDFGUARD_TEST_VAULT_SECRET_NAME";

    private static string SecretName => Environment.GetEnvironmentVariable(SecretNameVariable)!;

    private static async Task<HashiCorpVaultSecretCache> CreateAsync()
    {
        var address = new Uri(Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_ADDR") ?? "https://127.0.0.1:8200");
        var token = new StaticVaultToken(Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_TOKEN")!);
        return new HashiCorpVaultSecretCache(address, token, await TestRing.CreateAsync(),
            new HashiCorpVaultSecretCacheOptions { HttpMessageHandler = Handler });
    }

    // Trusts HKDFGUARD_TEST_VAULT_CACERT, and only it, when set.
    private static readonly HttpMessageHandler? Handler = Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_CACERT") is { Length: > 0 } path
        ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions =
            {
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(X509CertificateLoader.LoadCertificateFromFile(path));
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return certificate is not null && chain.Build(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
                },
            },
        }
        : null;

    [HashiCorpVaultFact]
    public async Task Decrypt_RevealsTheSecret()
    {
        using var cache = await CreateAsync();

        Assert.True(cache.TryGetMaxDecryptedLength(SecretName, out var max));
        Assert.True(cache.Decrypt(SecretName, new byte[max]) > 0);
    }

    [HashiCorpVaultFact]
    public async Task DecryptAsync_RevealsTheSecret()
    {
        using var cache = await CreateAsync();

        var max = await cache.GetMaxDecryptedLengthAsync(SecretName);
        Assert.True(max > 0);
        Assert.True(await cache.DecryptAsync(SecretName, new byte[max].AsMemory()) > 0);
    }

    [HashiCorpVaultFact]
    public async Task Decrypt_OfASecretThatDoesNotExist_ReturnsZero()
    {
        using var cache = await CreateAsync();

        Assert.Equal(0, cache.Decrypt($"hkdfguard/missing-{Guid.NewGuid():N}", new byte[16]));
    }
}

/// <summary>
/// A test that reads from a real Vault; reported as skipped unless
/// <see cref="HashiCorpVaultSecretCacheIntegrationTests.SecretNameVariable"/> is set.
/// </summary>
public sealed class HashiCorpVaultFactAttribute : FactAttribute
{
    public HashiCorpVaultFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(HashiCorpVaultSecretCacheIntegrationTests.SecretNameVariable)))
            Skip = $"Set {HashiCorpVaultSecretCacheIntegrationTests.SecretNameVariable} (with HKDFGUARD_TEST_VAULT_ADDR and HKDFGUARD_TEST_VAULT_TOKEN) to a secret's path#key to run Vault cache integration tests.";
    }
}
