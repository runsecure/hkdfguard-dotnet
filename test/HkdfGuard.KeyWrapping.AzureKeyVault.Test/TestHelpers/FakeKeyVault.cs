using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace HkdfGuard.KeyWrapping.AzureKeyVault.Test.TestHelpers;

/// <summary>
/// An in-memory Key Vault: named RSA and EC P-256 keys, each with versions, doing real RSA-OAEP-256
/// and ES256 so wrapped DEKs and signatures behave as Key Vault's do. Every call is recorded, and
/// any operation can be made to fail.
/// </summary>
internal sealed class FakeKeyVault : IDisposable
{
    public static readonly Uri VaultUri = new("https://hkdfguard-test.vault.azure.net/");
    public const string WrappingKeyName = "hkdfguard-wrap";
    public const string SigningKeyName = "hkdfguard-sign";

    private readonly Dictionary<string, List<(string Version, AsymmetricAlgorithm Key)>> _keys = new(StringComparer.OrdinalIgnoreCase);

    public FakeKeyVault()
    {
        AddVersion(WrappingKeyName, RSA.Create(2048));
        AddVersion(SigningKeyName, ECDsa.Create(ECCurve.NamedCurves.nistP256));
    }

    public static Uri WrappingKeyId => new(VaultUri, $"keys/{WrappingKeyName}");
    public static Uri SigningKeyId => new(VaultUri, $"keys/{SigningKeyName}");

    /// <summary>Every call, as "operation key-id".</summary>
    public List<string> Calls { get; } = [];

    /// <summary>Makes the named operation ("wrap", "unwrap", "sign", "verify") throw.</summary>
    public Dictionary<string, Exception> Failures { get; } = new(StringComparer.Ordinal);

    /// <summary>Rewrites what an operation reports as the key it used.</summary>
    public Func<string, string>? ReportedKeyId { get; set; }

    /// <summary>Rewrites a signature before it is returned.</summary>
    public Func<byte[], byte[]>? SignatureOverride { get; set; }

    /// <summary>Rewrites a revealed key before it is returned.</summary>
    public Func<byte[], byte[]>? UnwrapOverride { get; set; }

    /// <summary>The last revealed key returned, so tests can check the wrapper zeroed it.</summary>
    public byte[]? LastRevealed { get; private set; }

    /// <summary>The last plaintext wrap was given, as received.</summary>
    public byte[]? LastWrapped { get; private set; }

    public string AddVersion(string name, AsymmetricAlgorithm key)
    {
        var version = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        if (!_keys.TryGetValue(name, out var versions))
            _keys[name] = versions = [];
        versions.Add((version, key));
        return version;
    }

    public string CurrentVersion(string name) => _keys[name][^1].Version;

    /// <summary>Purges one version of a key, as deleting it from the vault would.</summary>
    public void Purge(string name, string version) => _keys[name].RemoveAll(v => v.Version == version);

    public RSA PublicWrappingKey() => (RSA)_keys[WrappingKeyName][^1].Key;

    public CryptographyClient Client(Uri keyId) => new Client(this, keyId);

    internal (string KeyId, AsymmetricAlgorithm Key) Resolve(Uri keyId)
    {
        var id = new KeyVaultKeyIdentifier(keyId);
        if (!_keys.TryGetValue(id.Name, out var versions))
            throw new RequestFailedException(404, "Key not found.", "KeyNotFound", null);

        var match = id.Version is null ? versions[^1] : versions.FirstOrDefault(v => v.Version == id.Version);
        if (match.Key is null)
            throw new RequestFailedException(404, "Key version not found.", "KeyNotFound", null);

        var resolved = $"{VaultUri.AbsoluteUri}keys/{id.Name}/{match.Version}";
        return (ReportedKeyId is { } report ? report(resolved) : resolved, match.Key);
    }

    internal void Record(string operation, Uri keyId)
    {
        Calls.Add($"{operation} {keyId}");
        if (Failures.TryGetValue(operation, out var failure))
            throw failure;
    }

    internal void Wrapped(byte[] plaintext) => LastWrapped = plaintext.ToArray();

    internal byte[] Revealed(byte[] key)
    {
        LastRevealed = UnwrapOverride?.Invoke(key) ?? key;
        return LastRevealed;
    }

    internal byte[] Signed(byte[] signature) => SignatureOverride?.Invoke(signature) ?? signature;

    public void Dispose()
    {
        foreach (var (_, key) in _keys.Values.SelectMany(v => v))
            key.Dispose();
    }
}

/// <summary>A CryptographyClient over one key identifier in a <see cref="FakeKeyVault"/>.</summary>
internal sealed class Client(FakeKeyVault vault, Uri keyId) : CryptographyClient
{
    public override Task<WrapResult> WrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key, CancellationToken cancellationToken = default)
    {
        vault.Record("wrap", keyId);
        Assert.Equal(KeyWrapAlgorithm.RsaOaep256, algorithm);
        vault.Wrapped(key);
        var (id, rsa) = vault.Resolve(keyId);
        var encrypted = ((RSA)rsa).Encrypt(key, RSAEncryptionPadding.OaepSHA256);
        return Task.FromResult(CryptographyModelFactory.WrapResult(id, encrypted, algorithm));
    }

    public override Task<UnwrapResult> UnwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey, CancellationToken cancellationToken = default)
    {
        vault.Record("unwrap", keyId);
        Assert.Equal(KeyWrapAlgorithm.RsaOaep256, algorithm);
        var (id, rsa) = vault.Resolve(keyId);
        byte[] key;
        try
        {
            key = ((RSA)rsa).Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException e)
        {
            throw new RequestFailedException(400, "Unwrap failed.", "BadParameter", e);
        }

        return Task.FromResult(CryptographyModelFactory.UnwrapResult(id, vault.Revealed(key), algorithm));
    }

    public override Task<SignResult> SignDataAsync(SignatureAlgorithm algorithm, byte[] data, CancellationToken cancellationToken = default)
    {
        vault.Record("sign", keyId);
        Assert.Equal(SignatureAlgorithm.ES256, algorithm);
        var (id, ec) = vault.Resolve(keyId);
        var signature = ((ECDsa)ec).SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Task.FromResult(CryptographyModelFactory.SignResult(id, vault.Signed(signature), algorithm));
    }

    public override Task<VerifyResult> VerifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature, CancellationToken cancellationToken = default)
    {
        vault.Record("verify", keyId);
        Assert.Equal(SignatureAlgorithm.ES256, algorithm);
        var (id, ec) = vault.Resolve(keyId);
        var valid = ((ECDsa)ec).VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Task.FromResult(CryptographyModelFactory.VerifyResult(id, valid, algorithm));
    }
}
