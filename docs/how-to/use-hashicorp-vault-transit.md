# Wrap keys with HashiCorp Vault transit

This page sets up a key in a HashiCorp Vault transit secrets engine as HkdfGuard's KEK and uses it
from .NET with `HashiCorpVaultTransitKeyWrapper`, in place of the native TPM, Secure Enclave or
Platform Crypto Provider KEK.

Use it when your applications already authenticate to Vault, or run somewhere a cloud KMS isn't
available, and you want key access controlled by Vault policy and recorded in Vault's audit log
rather than tied to one machine's TPM.

To run the transit integration tests against a Vault dev server, see
[Run the HashiCorp Vault transit integration tests](run-hashicorp-vault-transit-integration-tests.md).

## How it differs from the native wrapper

| | Native (`NativeHkdfKeyWrapperV1`) | Vault transit (`HashiCorpVaultTransitKeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | An `aes256-gcm96` transit key |
| Identified by | A service name | Vault's address and the key's name |
| Who may wrap and unwrap | Local accounts and groups the native library allows | Tokens whose policy grants `update` on the key's `encrypt`, `decrypt` and `datakey/wrapped` paths |
| Each call | Local, synchronous | A request to Vault's HTTP API, recorded in Vault's audit log |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in managed code; who else is trusted is set with `KeyFileTrust` |
| Install | The native package | Nothing beyond the NuGet package: it talks to Vault's HTTP API directly |

Wrapped DEKs aren't interchangeable. A key file wrapped by one wrapper can't be unwrapped by the
other, so each DEK belongs to the wrapper that created it. A transit-wrapped DEK is Vault's
ciphertext as it returns it, `vault:v1:...`, about 89 bytes of ASCII.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The wrapper needs an AEAD key for its context (associated data) |
| `derived` | `false` (the default) | A derived key needs a `context` on every request, which the wrapper doesn't send. Worse, a key that *isn't* derived silently ignores one, so the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

Rotate it with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version; existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file is rewrapped.

## 2. Grant each role only what it calls

Give `update`, and never `create`, on exactly the paths each role uses. `transit/encrypt/{name}`
creates a key that doesn't exist yet when the token has `create`, so with it a mistyped key name
would quietly wrap DEKs under a brand-new key.

A release pipeline that creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only
if it generates ephemeral keys at startup.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with (AppRole, Kubernetes, a certificate,
a cloud IAM role).

## 3. Give the process a token

Every request is made with a token from an `IVaultTokenSource`. Logging in, renewing and replacing
the token is the source's job, so any auth method can sit behind the wrapper. The token is copied
into a pinned buffer the wrapper zeroes once the request has been sent, rather than handed over as a
string.

`StaticVaultTokenSource` holds a token you already have, such as one a Vault Agent wrote to a sink
file. Nothing renews it, so once it expires every request fails with 403:

```csharp
using HkdfGuard.KeyWrapping.HashiCorpVault;

using var token = new StaticVaultTokenSource(Environment.GetEnvironmentVariable("VAULT_TOKEN"));
```

For a long-running service, prefer a Vault Agent on loopback with `use_auto_auth_token`, which
renews the token itself, or implement `IVaultTokenSource` over your auth method.

> **Note:** this is not the cache's `IVaultTokenProvider`. That one hands over a token protected by
> the key ring; a key wrapper runs before there is a key ring, so it can't.

## 4. Create the wrapper

Add the package:

```powershell
dotnet add package HkdfGuard.KeyWrapping.HashiCorpVault
```

> **TODO (maintainer):** confirm this package ID once the package is published.

```csharp
using HkdfGuard.KeyWrapping.HashiCorpVault;

using var wrapper = new HashiCorpVaultTransitKeyWrapper(
    new Uri("https://vault.example.com:8200"),
    keyName: "myapp-kek",
    tokenSource: token,
    context: "com.example.myapp");
```

- **The address must be https**, except on a loopback address (a local Vault Agent or dev server):
  every request carries a token, and wrap and unwrap carry plaintext DEKs. A path is kept as a
  prefix, for Vault behind a reverse proxy. The wrapper's own HTTP handler follows no redirects,
  which would carry the token elsewhere; a handler you supply in the options that does is refused
  unless you set `AllowRedirects`.
- **The context** is bound into every wrapped DEK as Vault's `associated_data` and must be given
  again, exactly, to reveal it. Use the same value on every wrapper that handles one application's
  key files. It isn't a secret and must not hold one.
- **With a context, `GenerateAndWrapAsync` generates the DEK in your process** and wraps it with
  `encrypt`, because `datakey/wrapped` ignores `associated_data`. Without one, Vault generates it
  and returns it wrapped only, so the plaintext DEK never leaves Vault on that call. Choose a context
  for the binding, or none for generation in Vault.
- **Old Vaults are refused, not trusted.** If Vault answers that it ignored a parameter, as one
  too old for `associated_data` does, the call fails rather than return a DEK bound to no context.
- **Dispose the wrapper** to release its connections, but only once nothing uses it, including a
  `KeyRing`'s background refresh. It doesn't dispose the token source or a handler you supply.

Options (`HashiCorpVaultTransitKeyWrapperOptions`) set a mount other than `transit`, a Vault
Enterprise namespace, the per-attempt timeout (30 seconds), and retries: a request that gets no
answer, loses its connection, times out, or is answered 429 or a 5xx other than 501 is retried 3
times by default, waiting 200 ms and doubling, plus up to 100 ms of jitter. To trust a private CA,
supply a `SocketsHttpHandler` with `AllowAutoRedirect = false`:

```csharp
var options = new HashiCorpVaultTransitKeyWrapperOptions
{
    MountPath = "transit/team-a",
    Namespace = "team-a/prod",
    HttpMessageHandler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        SslOptions = { RemoteCertificateValidationCallback = /* trust your CA */ },
    },
};
```

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere:

```csharp
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;

await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(wrapper)
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(300)
    .WithEphemeralKey(version: 1)
    .BuildAsync();
```

Everything encrypted under an ephemeral key is lost when the process exits. Data you store needs a
key file.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, logged in as the pipeline role from
step 2:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

To wrap a key the pipeline already holds, such as an `AesGcmPipelineDataProtector`'s, call
`WrapAsync` with it and zero your copy afterwards, as
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file) shows.

Key files are read only from where no untrusted account could have written or replaced them: anyone
who can replace a key file *and* call `encrypt` on the key could otherwise choose your application's
DEK. The rules, the folder setup and `KeyFileTrust` for a deployer account are the same as for AWS
KMS; see [Where key files can live](use-aws-kms.md#where-key-files-can-live). Pass the
`KeyFileTrust` as the wrapper's `keyFileTrust` argument.

## 7. Use the key file

```csharp
await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(wrapper)
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(300)
    .WithKeyFile(version: 1, pathToFile: @"C:\HkdfGuardKeys\myapp\v1.key")
    .BuildAsync();
```

`BuildAsync` calls `decrypt` once per key, so the application fails to start if Vault can't be
reached or refuses the key. Each key then calls `decrypt` once per `KeyRefreshInterval`: at 300
seconds, 8,640 requests per key per process every 30 days, each one in the audit log.

## If something goes wrong

Every Vault failure is a `CryptographicException` whose message gives Vault's status and errors;
an `HttpRequestException` (with `StatusCode`), `IOException` or timeout is its `InnerException`. A
failed unwrap zeroes the caller's buffer. A token source's own failure propagates as it is.

| The message names | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The token's policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 BadRequest` ... `encryption key not found` | No key by that name in this mount (or namespace) | Check the key name, `MountPath` and `Namespace` |
| `400 BadRequest` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with a different context | Restore the file; use the key and context it was created with |
| `400 BadRequest` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 BadRequest` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file under the current version |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 ServiceUnavailable` | Vault is sealed, or electing a leader, beyond the retries | Unseal Vault; check its HA status |
| `no answer within` | No answer within `Timeout`, on every attempt | Check the address and network path |
| `InvalidOperationException` ... `token source` | The token source supplied no token, or one with spaces or non-ASCII characters | Check what the source reads |

Reading a key file fails before Vault is called; see
[Wrap keys with AWS KMS](use-aws-kms.md#if-something-goes-wrong) for those errors.
