# Wrap keys with Azure Key Vault

This page sets up two Azure Key Vault keys as HkdfGuard's KEK and uses them from .NET with
`AzureKeyVaultKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider
KEK.

## Why two keys

A Key Vault (Standard or Premium) offers RSA and EC keys. Only RSA keys can wrap; EC keys can only
sign and verify. RSA-OAEP wrapping needs nothing but the public key, which isn't secret, so on its
own anyone could produce a wrapped DEK holding a key *they* chose, and your application would encrypt
new data under it.

So `AzureKeyVaultKeyWrapper` uses:

- an **RSA key** (2048 or 3072 bits) to wrap and unwrap each DEK, with RSA-OAEP-256;
- a separate **EC P-256 key** to sign each wrapped DEK, with ES256.

Signing happens inside Key Vault and needs the `sign` permission. Unwrap checks the signature
before it unwraps anything. So a key file the application accepts proves it was made by a principal
allowed to sign: give that permission to the pipeline that creates key files, never to the
application.

| | AWS KMS | Azure Key Vault |
|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key |
| Context binding | Encryption context (AAD) | A context string bound into the signature |
| New DEKs | Generated inside KMS | Generated in the process, wrapped, then zeroed |

Wrapped DEKs aren't interchangeable between wrappers: a key file belongs to the wrapper that made it.

## 1. Create the keys

Create a vault, or use an existing one, with **purge protection** turned on. Deleting a key makes
every DEK wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable;
purge protection keeps a deleted key recoverable for its retention period.

Create the two keys, each allowed only the operations it needs:

```bash
az keyvault key create --vault-name myvault --name myapp-wrap --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault key create --vault-name myvault --name myapp-sign --kty EC --curve P-256 --ops sign verify
```

In the portal: **Keys**, **Generate/Import**, then for the first choose **RSA** and 2048 or 3072
bits, and for the second **EC** and **P-256**. After creating each, open its version and clear every
permitted operation except the two above.

Use 2048 or 3072 bits for the RSA key. A 4096-bit key's wrapped DEK is too large for a key file
(`WrappedKeyLimits.MaxBytes`, 512 bytes), and wrapping under one is refused.

Copy each key's **key identifier** without the version, for example
`https://myvault.vault.azure.net/keys/myapp-wrap`.

## 2. Grant each identity only what it calls

With Azure RBAC, assign roles on each **key**, not the vault:

| Identity | On the RSA key | On the EC key |
|---|---|---|
| Release pipeline that creates key files | Key Vault Crypto Service Encryption User | Key Vault Crypto User |
| Application | Key Vault Crypto Service Encryption User | Key Vault Crypto Service Encryption User |

The application's role on the EC key lets it read the public key, and the SDK verifies with it
locally; it doesn't include `sign`.

```bash
az role assignment create --assignee <app-principal-id> --role "Key Vault Crypto Service Encryption User" \
  --scope "$(az keyvault show -n myvault --query id -o tsv)/keys/myapp-wrap"
```

With vault access policies instead, which apply to the whole vault: the pipeline gets **Get**,
**Wrap Key** and **Sign**; the application **Get**, **Unwrap Key** and **Verify**.

> **Security:** never give the application `sign` on the EC key (Key Vault Crypto User, Crypto
> Officer, or the Sign access policy). With it, anyone controlling the application, and able to
> replace a key file, could choose its DEK.

## 3. Give the process a credential

Every call is authorized by an Azure `TokenCredential`. Deployed, use a **managed identity**
(`new ManagedIdentityCredential(...)`, or `DefaultAzureCredential`, which finds it); on a developer
machine, `DefaultAzureCredential` uses your `az login`. Don't give a deployed process a client
secret.

## 4. Create the wrapper

```powershell
dotnet add package HkdfGuard.KeyWrapping.AzureKeyVault
dotnet add package Azure.Identity
```

> **TODO (maintainer):** confirm this package ID once the package is published.

```csharp
using Azure.Identity;
using HkdfGuard.KeyWrapping.AzureKeyVault;

var wrapper = new AzureKeyVaultKeyWrapper(
    wrappingKeyId: new Uri("https://myvault.vault.azure.net/keys/myapp-wrap"),
    signingKeyId: new Uri("https://myvault.vault.azure.net/keys/myapp-sign"),
    credential: new DefaultAzureCredential(),
    context: "com.example.myapp");
```

- **Give key identifiers without a version.** New key files then use each key's current version,
  and every key file records the versions it was made with, so both keys can be rotated in Key
  Vault with no change here. Keep an old version enabled for as long as key files made with it are
  in use.
- **The context** is bound into every key file's signature and must be given again, exactly, to
  reveal it. Use one value per application, so a key file made for one can't be used by another
  that shares the keys. It isn't secret.

Use it exactly as any other key wrapper: `KeyRingBuilder.WithKeyWrapper(wrapper)`, with ephemeral
keys or key files.

## 5. Create and use key files

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

```csharp
using HkdfGuard.Abstractions;

var wrapped = new byte[WrappedKeyLimits.MaxBytes];
int length = await wrapper.GenerateAndWrapAsync(wrapped);
await File.WriteAllBytesAsync(@"C:\HkdfGuardKeys\myapp\v1.key", wrapped.AsMemory(0, length));
```

`GenerateAndWrapAsync` generates the DEK in the pipeline's process, since Key Vault has no "generate
data key", and zeroes it once wrapped. To wrap the key of an `AesGcmPipelineDataProtector`, use
`WrapAsync` as in [Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file).

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live),
and pass a `KeyFileTrust` as the wrapper's `keyFileTrust` argument if the pipeline writes key files
as an account of its own.

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `KeyRefreshInterval`: a verify, which the SDK does
locally once it has the public key, and an unwrap call to Key Vault. See
[Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the trade-off, and
[Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/) for what each operation
costs: RSA 3072 and EC keys are billed at a higher rate than RSA 2048.

## Run the integration tests

`AzureKeyVaultIntegrationTests` make real calls. They are reported as skipped, never passed, until
both keys are named in `azure.runsettings`.
[Run the Azure Key Vault integration tests](run-azure-key-vault-integration-tests.md) sets up a test
vault and both keys, and runs them.

## If something goes wrong

Every failure is a `CryptographicException`; for a Key Vault refusal the message names its error
code and HTTP status, and the Azure exception is its `InnerException`. A failed unwrap zeroes the
caller's buffer. Reading a key file fails as described for
[AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `Forbidden (HTTP 403)` | The identity lacks the operation on that key | Step 2 |
| `KeyNotFound (HTTP 404)` | The identifier is wrong, or the key version a key file names was purged | Check the identifier; restore the version |
| `signature doesn't verify` | The key file was altered, made under another context, or not signed by a principal allowed to sign | Restore it; use the same context |
| `not a wrapped DEK written by AzureKeyVaultKeyWrapper` | The file isn't one of this wrapper's key files | Check the path and wrapper |
| `Use a 2048- or 3072-bit RSA key` | The wrapping key is 4096 bits | Create a smaller RSA key |
| `The signing key must be an EC P-256 key` | The signing key is another curve, or RSA | Create an EC P-256 key |
| `reported key ... instead` | Key Vault answered for a different key | Check both identifiers |
| `CredentialUnavailableException`, `AuthenticationFailedException` (inner) | No credential could get a token | Step 3 |
