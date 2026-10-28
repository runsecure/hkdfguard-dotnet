# Wrap keys with Google Cloud KMS

This page sets up a Google Cloud KMS key as HkdfGuard's KEK and uses it from .NET with
`GoogleKmsKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider KEK.

## How it compares

Cloud KMS works like AWS KMS: one symmetric key, used through `Encrypt` and `Decrypt`, which never
leaves Cloud KMS.

| | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign | One symmetric key |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key | Principals allowed `useToEncrypt` |
| Context binding | Encryption context (AAD) | A context string bound into the signature | A context string bound as AAD |
| New DEKs | Generated inside KMS | Generated in the process, wrapped, then zeroed | Generated in the process, wrapped, then zeroed |

`GoogleKmsKeyWrapper`:

- **Pins the key.** `Decrypt` is always called against the key you configure, and Cloud KMS
  refuses a ciphertext made under any other key.
- **Binds a fixed HkdfGuard label and your context** into every wrapped DEK as additional
  authenticated data (AAD). A ciphertext the same key made for anything else isn't accepted as a
  DEK.
- **Checksums every request and response with CRC32C**, as Google recommends, so data corrupted
  in transit is refused.

Wrapped DEKs aren't interchangeable between wrappers: a key file belongs to the wrapper that made
it.

## 1. Create the key

Enable the API, then create a key ring and a key whose purpose is **encryption**
(`ENCRYPT_DECRYPT`, algorithm `GOOGLE_SYMMETRIC_ENCRYPTION`):

```bash
gcloud services enable cloudkms.googleapis.com --project my-project

gcloud kms keyrings create myapp --location us-east1 --project my-project
gcloud kms keys create myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --purpose encryption --protection-level hsm \
  --rotation-period 90d --next-rotation-time 2027-01-01T00:00:00Z
```

| Setting | Choose | Why |
|---|---|---|
| Purpose | **Symmetric encrypt/decrypt** | `GoogleKmsKeyWrapper` calls `Encrypt` and `Decrypt`, which only this purpose accepts |
| Protection level | **HSM** (or Software) | HSM keeps the key in a FIPS 140-2 Level 3 module; both work the same here |
| Rotation | Automatic, if you like | A ciphertext names the version that made it, so rotation needs nothing here |
| Location | Where the application runs | Key rings can't be moved or deleted; the name is part of every call |

In the console: **Security**, **Key Management**, **Create key ring**, then **Create key** with
**Purpose: Symmetric encrypt/decrypt**.

> **Security:** destroying a key version makes every DEK wrapped under it, and all data encrypted
> under those DEKs, permanently unrecoverable. Cloud KMS waits before destroying a version (30 days
> by default; `--destroy-scheduled-duration` sets it when the key is created), during which it can
> be restored. Keep every version that made a key file in use enabled.

Copy the key's **resource name**, for example
`projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap`:

```bash
gcloud kms keys describe myapp-wrap --keyring myapp --location us-east1 --project my-project --format "value(name)"
```

Give the key, never a key version (`.../cryptoKeyVersions/1`): the wrapper refuses one. Encrypt
uses the key's primary version, and Decrypt finds the version from the ciphertext.

## 2. Grant each identity only what it calls

Grant roles on the **key**, not the project or key ring:

| Identity | Role on the key |
|---|---|
| Release pipeline that creates key files | Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`) |
| Application | Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`) |

```bash
gcloud kms keys add-iam-policy-binding myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter
```

> **Security:** give the application decrypt without encrypt. Symmetric encryption needs no
> secret beyond permission to use the key, so any principal allowed `useToEncrypt` can create a key
> file the application accepts, holding a DEK of its choosing. Keep encrypt with the pipeline.

## 3. Give the process a credential

The client signs in with Application Default Credentials (ADC). Deployed, use the **attached
service account** (Compute Engine, Cloud Run, GKE Workload Identity); outside Google Cloud, use
Workload Identity Federation. On a developer machine, ADC uses
`gcloud auth application-default login`. Don't give a deployed process a service account key file.

## 4. Create the wrapper

```powershell
dotnet add package HkdfGuard.KeyWrapping.GoogleKms
```

> **TODO (maintainer):** confirm this package ID once the package is published.

```csharp
using Google.Cloud.Kms.V1;
using HkdfGuard.KeyWrapping.GoogleKms;

var kms = await KeyManagementServiceClient.CreateAsync(); // Application Default Credentials
var wrapper = new GoogleKmsKeyWrapper(kms,
    "projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
    context: "com.example.myapp");
```

- **The context** is bound into every key file and must be given again, exactly, to reveal it.
  Use one value per application, so a key file made for one can't be used by another that shares
  the key. It isn't secret.
- **Create one client and keep it.** `KeyManagementServiceClient` holds a gRPC channel; it is safe
  to share between threads and wrappers.

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

`GenerateAndWrapAsync` generates the DEK in the pipeline's process, since Cloud KMS has no
"generate data key", and zeroes it once wrapped. To wrap the key of an
`AesGcmPipelineDataProtector`, use `WrapAsync` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file).

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live),
and pass a `KeyFileTrust` as the wrapper's `keyFileTrust` argument if the pipeline writes key files
as an account of its own.

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `KeyRefreshInterval`: one `Decrypt` call to Cloud
KMS. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the
trade-off, and [Cloud KMS pricing](https://cloud.google.com/kms/pricing) for what each operation
and active key version costs: HSM keys cost more than software keys.

## Run the integration tests

`GoogleKmsIntegrationTests` make real calls. They are reported as skipped, never passed, until the
key is named in `google.runsettings`.
[Run the Google Cloud KMS integration tests](run-google-kms-integration-tests.md) sets up a test key
and runs them.

## If something goes wrong

Every failure is a `CryptographicException`; for a Cloud KMS refusal the message names the gRPC
status and Google's detail, and the `RpcException` is its `InnerException`. A failed unwrap zeroes
the caller's buffer. Reading a key file fails as described for
[AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `PermissionDenied` | The identity lacks the role on the key, or the API isn't enabled | Step 2; `gcloud services enable cloudkms.googleapis.com` |
| `NotFound` | The resource name is wrong | Step 1's `describe` command |
| `InvalidArgument: Decryption failed` | The key file was altered, made under another key or context, or by another tool | Restore it; use the same key and context |
| `FailedPrecondition` | The key version the key file names is disabled or destroyed | Re-enable or restore the version |
| `isn't a Cloud KMS key's resource name` | The name is malformed, or names a key version | Give `projects/.../cryptoKeys/{key}` |
| `corrupted in transit` | A checksum didn't match | Retry; if it persists, check proxies between the process and Cloud KMS |
| `Unauthenticated`, or an ADC error | No credential could be found or get a token | Step 3 |
