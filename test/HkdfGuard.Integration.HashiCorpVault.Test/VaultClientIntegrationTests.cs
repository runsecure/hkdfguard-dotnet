using System.Net;
using HkdfGuard.Integration.HashiCorpVault.Schema;
using HkdfGuard.Integration.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.Integration.HashiCorpVault.Test;

/// <summary>
/// The client against a real Vault dev server, which these tests write to - a KV version 2 engine at
/// "secret" (a dev server's default), under hkdfguard-client-test/:
/// <code>
/// HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
/// HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem dotnet test test/HkdfGuard.Integration.HashiCorpVault.Test
/// </code>
/// or with vault.runsettings. Without HKDFGUARD_TEST_VAULT_TOKEN, or with an address that isn't
/// loopback, every test here is reported as skipped - never as passed. HKDFGUARD_TEST_VAULT_CACERT,
/// read through <see cref="VaultTlsOptions.ServerCertificateFile"/>, is needed only for a server
/// certificate the operating system doesn't trust.
/// </summary>
public class VaultClientIntegrationTests
{
    private static Uri Address => new(Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_ADDR") ?? "https://127.0.0.1:8200");

    private static async Task<VaultClient> CreateAsync()
    {
        var ring = await TestRing.CreateAsync();
        var protector = ring.CreateProtector(VaultClient.TokenPurpose);
        return new VaultClient(protector, new VaultClientOptions
        {
            Address = Address,
            Token = StaticVaultToken.Protect(protector, Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_TOKEN")),
            Tls = { ServerCertificateFile = Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_CACERT") is { Length: > 0 } ca ? ca : null },
        });
    }

    [VaultDevServerFact]
    public async Task Health_IsReadWithoutAToken()
    {
        using var client = await CreateAsync();
        client.ClearToken();

        var health = await client.System.ReadHealthStatusAsync();

        Assert.True(health!.Data!["initialized"].GetBoolean());
    }

    [VaultDevServerFact]
    public async Task ASecret_IsWrittenReadListedAndDeleted_ThroughTheGeneratedApi()
    {
        using var client = await CreateAsync();
        var path = $"hkdfguard-client-test/{Guid.NewGuid():N}";
        var secret = new VaultRequestOptions { MountPath = "secret" };

        var written = await client.Secrets.KvV2WriteAsync(path, new KvV2WriteRequest
        {
            Data = new Dictionary<string, object?> { ["password"] = "s3cret", ["n"] = 7 },
        }, secret);
        var read = await client.Secrets.KvV2ReadAsync(path, secret);
        var listed = await client.Secrets.KvV2ListAsync("hkdfguard-client-test", secret);
        await client.Secrets.KvV2DeleteMetadataAndAllVersionsAsync(path, secret);

        Assert.Equal(1, written!.Data!.Version);
        Assert.Equal("s3cret", read!.Data!.Data!["password"].GetString());
        Assert.Equal(7, read.Data.Data["n"].GetInt32());
        Assert.Contains(path.Split('/')[1], listed!.Data!.Keys!);
        var e = await Assert.ThrowsAsync<VaultResponseException>(() => client.Secrets.KvV2ReadAsync(path, secret));
        Assert.True(VaultClient.IsErrorStatus(e, HttpStatusCode.NotFound));
    }

    [VaultDevServerFact]
    public async Task TheGenericMethods_ReachAnyPath()
    {
        using var client = await CreateAsync();
        var path = $"secret/data/hkdfguard-client-test/{Guid.NewGuid():N}";

        await client.WriteAsync(path, new Dictionary<string, object?> { ["data"] = new Dictionary<string, object?> { ["k"] = "v" } });
        var read = await client.ReadAsync(path);
        await client.DeleteAsync(path.Replace("/data/", "/metadata/"));

        Assert.Equal("v", read!.Data!["data"].GetProperty("k").GetString());
    }

    [VaultDevServerFact]
    public async Task AWrappedResponse_IsUnwrappedWithItsProtectedToken()
    {
        using var client = await CreateAsync();
        var path = $"hkdfguard-client-test/{Guid.NewGuid():N}";
        var secret = new VaultRequestOptions { MountPath = "secret" };
        await client.Secrets.KvV2WriteAsync(path, new KvV2WriteRequest { Data = new Dictionary<string, object?> { ["k"] = "wrapped" } }, secret);

        var wrapped = await client.Secrets.KvV2ReadAsync(path, secret with { ResponseWrappingTtl = TimeSpan.FromMinutes(1) });
        var unwrapped = await client.UnwrapAsync<KvV2ReadResponse>(wrapped!.WrapInfo!.Token!);
        await client.Secrets.KvV2DeleteMetadataAndAllVersionsAsync(path, secret);

        Assert.Null(wrapped.Data);
        Assert.Equal("wrapped", unwrapped!.Data!.Data!["k"].GetString());
    }

    [VaultDevServerFact]
    public async Task ATokenCreated_IsProtected_AndWorks()
    {
        using var client = await CreateAsync();

        var created = await client.Auth.TokenCreateAsync(new TokenCreateRequest { Policies = ["default"], Ttl = "5m" });
        using var child = client.Clone();
        child.SetToken(created!.Auth!.ClientToken!);
        var self = await child.Auth.TokenLookUpSelfAsync();
        await child.Auth.TokenRevokeSelfAsync();

        Assert.Contains("default", self!.Data!["policies"].EnumerateArray().Select(p => p.GetString()));
    }
}

/// <summary>A test against a real Vault dev server; reported as skipped unless one is configured on loopback.</summary>
public sealed class VaultDevServerFactAttribute : FactAttribute
{
    public VaultDevServerFactAttribute()
    {
        var address = Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_ADDR");
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HKDFGUARD_TEST_VAULT_TOKEN")))
            Skip = "Set HKDFGUARD_TEST_VAULT_TOKEN (and HKDFGUARD_TEST_VAULT_ADDR) to a Vault dev server's to run Vault client integration tests.";
        else if (address is { Length: > 0 } && !(Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.IsLoopback))
            Skip = "The Vault client integration tests write secrets: HKDFGUARD_TEST_VAULT_ADDR must be a dev server on loopback.";
    }
}
