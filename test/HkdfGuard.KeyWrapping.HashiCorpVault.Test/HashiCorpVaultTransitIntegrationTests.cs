using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.KeyWrapping.HashiCorpVault.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.HashiCorpVault.Test;

/// <summary>
/// Real calls against a transit key the caller provides, with a token the caller provides - on a
/// dev server, the ones scripts/provision-vault-transit-test-key.sh creates and prints:
/// <code>
/// HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
/// HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
/// dotnet test test/HkdfGuard.KeyWrapping.HashiCorpVault.Test
/// </code>
/// Without HKDFGUARD_TEST_VAULT_TRANSIT_KEY every test here is reported as skipped - never as
/// passed. HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT names a mount other than "transit", and
/// HKDFGUARD_TEST_VAULT_CACERT a CA for a server certificate the operating system doesn't trust.
/// The token needs only update on encrypt, decrypt and datakey/wrapped for the keys; the tests never
/// create, rotate, read or delete a key.
/// </summary>
public class HashiCorpVaultTransitIntegrationTests
{
    private const string Context = "hkdfguard.integrationtest";

    private static HashiCorpVaultTransitKeyWrapper Create(string? context = Context, string? keyName = null)
        => new(VaultTransitTestEnvironment.Address, keyName ?? VaultTransitTestEnvironment.Key,
            new StaticVaultTokenSource(VaultTransitTestEnvironment.Token), context, options: VaultTransitTestEnvironment.Options);

    [VaultTransitIntegrationFact]
    public async Task WrapThenUnwrap_RoundTripsA32ByteDek()
    {
        using var wrapper = Create();
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.WrapAsync(dek, wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.Equal(dek, revealed);
    }

    [VaultTransitIntegrationFact]
    public async Task GenerateAndWrap_InVault_ProducesAWrappedDekThatReveals()
    {
        // No context: Vault generates the DEK with datakey/wrapped.
        using var wrapper = Create(context: null);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.False(revealed.All(b => b == 0));
    }

    [VaultTransitIntegrationFact]
    public async Task GenerateAndWrap_WithAContext_ProducesAWrappedDekThatReveals()
    {
        using var wrapper = Create();

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        var revealed = new byte[32];

        Assert.Equal(32, await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), revealed));
        Assert.False(revealed.All(b => b == 0));
    }

    [VaultTransitIntegrationFact]
    public async Task Unwrap_UnderAnotherContext_OrNone_IsRefused()
    {
        using var wrapper = Create();
        using var other = Create(context: "hkdfguard.integrationtest.other");
        using var none = Create(context: null);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () => await other.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
        await Assert.ThrowsAsync<CryptographicException>(async () => await none.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [VaultTransitIntegrationFact]
    public async Task Unwrap_WhenTampered_IsRefused()
    {
        using var wrapper = Create();

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);
        // Another base64 character, so it reaches Vault and fails there.
        wrapped[12] = wrapped[12] == (byte)'A' ? (byte)'B' : (byte)'A';

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
        Assert.Contains("400", exception.Message);
    }

    [VaultTransitOtherKeyFact]
    public async Task Unwrap_UnderAnotherKey_IsRefused()
    {
        using var wrapper = Create();
        using var other = Create(keyName: VaultTransitTestEnvironment.ConfiguredOtherKey);

        var wrapped = new byte[WrappedKeyLimits.MaxBytes];
        var length = await wrapper.GenerateAndWrapAsync(wrapped);

        await Assert.ThrowsAsync<CryptographicException>(async () => await other.UnwrapAsync(wrapped.AsMemory(0, length), new byte[32]));
    }

    [VaultTransitIntegrationFact]
    public async Task AnInvalidToken_IsRefusedWith403()
    {
        using var wrapper = new HashiCorpVaultTransitKeyWrapper(VaultTransitTestEnvironment.Address, VaultTransitTestEnvironment.Key,
            new StaticVaultTokenSource("hvs.not-a-real-token"), options: VaultTransitTestEnvironment.Options);

        var exception = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await wrapper.GenerateAndWrapAsync(new byte[WrappedKeyLimits.MaxBytes]));
        Assert.Contains("403", exception.Message);
    }

    [VaultTransitIntegrationFact]
    public async Task ACryptoProvider_GeneratesAndRevealsItsDekThroughVault()
    {
        using var wrapper = Create();
        await using var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(wrapper, expirySeconds: 60);

        var expected = "hello, vault transit"u8.ToArray();
        var plaintext = expected.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var encryptedLength = provider.Encrypt(plaintext, encrypted);
        var decrypted = new byte[provider.GetDecryptedAllocationLength(encryptedLength)];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, encryptedLength), decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }
}
