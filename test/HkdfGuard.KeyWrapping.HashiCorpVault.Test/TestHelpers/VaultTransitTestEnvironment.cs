using System.Security.Cryptography.X509Certificates;

namespace HkdfGuard.KeyWrapping.HashiCorpVault.Test.TestHelpers;

/// <summary>
/// The real Vault and transit key the integration tests run against, if one was given. The
/// address, token and CA are the same variables the Vault cache's integration tests read.
/// </summary>
public static class VaultTransitTestEnvironment
{
    public const string KeyVariable = "HKDFGUARD_TEST_VAULT_TRANSIT_KEY";
    public const string OtherKeyVariable = "HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY";
    public const string MountVariable = "HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT";
    public const string AddressVariable = "HKDFGUARD_TEST_VAULT_ADDR";
    public const string TokenVariable = "HKDFGUARD_TEST_VAULT_TOKEN";
    public const string CaCertVariable = "HKDFGUARD_TEST_VAULT_CACERT";

    public static string? ConfiguredKey => Get(KeyVariable);

    public static string? ConfiguredOtherKey => Get(OtherKeyVariable);

    public static string Key => ConfiguredKey ?? throw new InvalidOperationException($"{KeyVariable} is not set.");

    public static Uri Address => new(Get(AddressVariable) ?? "http://127.0.0.1:8200");

    public static string Token => Get(TokenVariable) ?? throw new InvalidOperationException($"{TokenVariable} is not set.");

    public static HashiCorpVaultTransitKeyWrapperOptions Options => new()
    {
        MountPath = Get(MountVariable) ?? "transit",
        HttpMessageHandler = Handler,
    };

    // Trusts HKDFGUARD_TEST_VAULT_CACERT, and only it, when set.
    private static readonly HttpMessageHandler? Handler = Get(CaCertVariable) is { } path
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

    private static string? Get(string variable) => Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value ? value : null;
}

/// <summary>
/// A test that makes real Vault transit calls; reported as skipped unless
/// <see cref="VaultTransitTestEnvironment.KeyVariable"/> names a key. Once it does, a failing call
/// is a test failure, never a silent pass.
/// </summary>
public sealed class VaultTransitIntegrationFactAttribute : FactAttribute
{
    public VaultTransitIntegrationFactAttribute()
    {
        if (VaultTransitTestEnvironment.ConfiguredKey is null)
            Skip = $"Set {VaultTransitTestEnvironment.KeyVariable} (with {VaultTransitTestEnvironment.AddressVariable} and {VaultTransitTestEnvironment.TokenVariable}) to a transit key to run Vault transit integration tests.";
    }
}

/// <summary>
/// A test that needs a second real transit key; reported as skipped unless
/// <see cref="VaultTransitTestEnvironment.KeyVariable"/> and
/// <see cref="VaultTransitTestEnvironment.OtherKeyVariable"/> are both set.
/// </summary>
public sealed class VaultTransitOtherKeyFactAttribute : FactAttribute
{
    public VaultTransitOtherKeyFactAttribute()
    {
        if (VaultTransitTestEnvironment.ConfiguredKey is null || VaultTransitTestEnvironment.ConfiguredOtherKey is null)
            Skip = $"Set {VaultTransitTestEnvironment.KeyVariable} and {VaultTransitTestEnvironment.OtherKeyVariable} to two transit keys to check one refuses the other's DEKs.";
    }
}
