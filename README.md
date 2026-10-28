# HkdfGuard

A C# library for protecting data-at-rest encryption keys using native, platform-backed key
management (TPM2 on Linux, Secure Enclave on macOS, the Platform Crypto Provider/TPM on Windows -
see `HkdfGuard.KeyWrapping.V1`) combined with AES-GCM for the actual data encryption. Application
code works against a `KeyRing` to encrypt/decrypt strings and binary data, with key-version
tracking and purpose-scoped Additional Authenticated Data (AAD).

## Key concepts

- **The KEK never enters this process, and a revealed DEK lives only in pinned memory.**
  Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native KMS library
  for the current OS (`NativeHkdfKeyWrapperV1`) - the KEK never leaves that native library. This
  library sees the wrapped payload and the revealed DEK. It holds the DEK in pinned memory for as
  long as that key is in use, and zeroes it when the ring is disposed, when the key fails closed
  because the KEK became unavailable, or, for an ephemeral key, when its retention ends; it never
  writes a plaintext DEK to disk.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself. `KeyRingBuilder` carries this,
  along with a key refresh/rotation policy, fluently.
- **One `IKeyWrapper` per KEK, not per wrapped payload.** `IKeyWrapper.UnwrapAsync` takes the
  wrapped payload as an explicit argument, so a single wrapper instance (bound only to a KEK - e.g. a
  `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped DEKs
  sharing that KEK, one per registered key file. Its methods (`WrapAsync`/`UnwrapAsync`/
  `GenerateAndWrapAsync`) are asynchronous so network-backed KEKs can be awaited; the native
  wrapper completes synchronously.
- **Cached, proactively-refreshed cipher sessions via `ICryptoProvider`.** A revealed DEK is
  bound into an internal cipher session once, not re-revealed on every Encrypt/Decrypt - the
  configured interval (`KeyRefreshInterval`, 1-300 seconds) sets how often that session is rebuilt
  from a fresh reveal.
  `ICryptoProvider` owns that refresh itself, and does it ahead of time: a background timer,
  ticking every `expirySeconds`, reveals and builds the next session, then swaps it in and
  disposes the outgoing one (zeroing its key) - so an Encrypt/Decrypt call never pays the unwrap
  cost itself; only the provider's constructor does, once, for the first session. Be precise
  about what a refresh is: it re-reveals the *same* DEK, so it is a periodic re-check that the
  KEK is still accessible (a revoked TPM/KMS grant is noticed within one interval), not a bound
  on how long the DEK value exists in memory. What happens when that check fails is the
  **refresh-failure policy**. A `KeyRing` fails closed by default: after
  `KeyRingBuilder.DefaultMaxRefreshFailures` (3) consecutive failed refreshes the provider
  disposes its sessions - zeroing every revealed copy of the DEK - raises an
  `hkdfguard.key_access_suspended` event, and every Encrypt/Decrypt throws
  `CryptographicException` until a later refresh succeeds, at which point service resumes with no
  restart. So revoking the KEK stops a running process within about `3 × KeyRefreshInterval`.
  `WithMaxRefreshFailures(n)` (or `HkdfGuardOptions.MaxRefreshFailures`) changes `n`, from 1 to
  100 (`RefreshFailurePolicy.MaxAllowedRefreshFailures`); pick it so that `n × KeyRefreshInterval`
  is longer than any KEK outage you'd rather ride out. 100 at the longest interval is about 8 h 20
  min; a larger limit would quietly fail open, so failing open has to be asked for explicitly.
  `WithFailOpenOnRefreshFailure()` (or `HkdfGuardOptions.FailOpenOnRefreshFailure`) opts out: the
  last good session then stays in use indefinitely, and revoking the KEK never stops the process.
  Either way, give the factory a logger - `new AesGcmCryptoProviderFactory(logger)` - and every
  failed refresh is logged as an error, a suspension as critical, and a resumption as
  information; under fail-open that error is the only sign the KEK is gone. (Providers created
  directly through `ICryptoProviderFactory` or `AesGcmCryptoProvider.CreateAsync` fail closed by
  default too, after `RefreshFailurePolicy.DefaultMaxRefreshFailures`; passing a null
  `maxRefreshFailures` explicitly opts them into fail-open.) The concrete
  session type itself (e.g. `AesGcmCryptoSession`) is an internal implementation detail - callers
  only ever see it through the public `ICryptoProvider` they were given (e.g.
  `AesGcmCryptoProvider`), which exposes Encrypt/Decrypt directly. `ICryptoProviderFactory` is the
  single seam `KeyRingBuilder` mints providers through, for each of the two ways a DEK is
  revealed: `CreateAsync` (wrapped-on-disk) and `CreateEphemeralAsync` (generated fresh via
  `IKeyWrapper.GenerateAndWrapAsync`). Both are asynchronous, because creating a provider reveals
  its first key through the key wrapper, which for a network-backed KEK is a remote call.
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  wrapped keys by an integer version. The highest version added automatically becomes the ring's
  `CurrentVersion` - no separate "mark as current" step, so it can never drift out of sync with
  what's actually registered.
- **Two kinds of key, two lifetimes.** The intended operating model:
  - *Deployment keys* (key files) exist so the application can **decrypt** what its pipeline
    wrote. Each deployment gets a fresh random DEK: the pipeline generates it
    (`AesGcmPipelineDataProtector`), protects that deployment's configuration with it, and hands it
    to the native wrapper to produce the key file. Nothing is carried forward from a previous
    deployment, so keys are never rotated in place and old versions never need to stay registered.
    How often keys rotate is therefore set by how often you deploy, and the library has no
    rotation setting of its own.
  - *Runtime keys* (`WithEphemeralKey`, registered at a higher version so they become
    `CurrentVersion`) are what the running process **encrypts** with - caches and other
    in-process protected values. A runtime key is generated at startup and is gone at the next
    restart, deliberately, and so is everything encrypted under it. **Never persist runtime
    ciphertext** - in a database, a file, a distributed cache, or anywhere else that outlives the
    process: after a restart nothing can decrypt it.

  What bounds any key's life is AES-GCM itself: with random 96-bit nonces, NIST SP 800-38D caps
  one key at 2^32 encryptions, past which a repeated nonce - which breaks both confidentiality and
  integrity for everything under that key - is no longer negligible. Decryption never consumes any
  of this, and a pipeline's few hundred writes are nothing against it. What consumes it is
  runtime encryption, and the budget belongs to the key, not the application: with a runtime key
  as `CurrentVersion`, every process has its own key, so the budget is per process per lifetime.
  (Only if many instances shared one file-backed key as their current version would their
  encryption rates add up against a single budget.) Per key:

  | Key lifetime (e.g. one process's uptime) | Sustained encrypt rate under that key that reaches 2^32 |
  |---|---|
  | 30 days | ~1,650 / s |
  | 90 days | ~550 / s |
  | 1 year | ~135 / s |

  `AesGcmCryptoProvider` counts its own encryptions (`EncryptionCount`), raises an
  `hkdfguard.encryption_budget_warning` event on the encrypt span that crosses 2^28, and refuses to
  encrypt - decryption keeps working - past 2^31 (`MaxEncryptionsPerKey`: half the NIST limit,
  because a per-process counter cannot see the other instances sharing the key). A background
  refresh re-reveals the same key, so it does not reset the count. Without an `ActivityListener`
  the only signal is the exception at the limit.

  **The count is kept per process, by design.** It is exact for an ephemeral key, which only one
  process ever holds. Key files carry what the deployment pipeline encrypted and are meant to be
  decrypted at runtime; every process that loads one, and every restart, starts a fresh count for
  it. **For encrypt operations, add an ephemeral key** (`WithEphemeralKey(2)` beside
  `WithKeyFile(1, ...)`) so new values are encrypted under it. If an application does encrypt
  values that must outlive the process under a key file, bound that key's use by deploying a new
  key file at a higher version regularly.
- **Purpose-scoped protectors.** `IDataProtector` binds a `name` (purpose) to every operation as
  AAD, so a value protected for one purpose can never be decrypted under another - even using the
  same underlying key.
- **Span-based, allocation-conscious API.** Byte and char spans are used throughout; secrets are
  zeroed immediately after use (via `CryptographicOperations.ZeroMemory`, which the runtime never
  optimizes away) and never returned as strings except for the final, already-encrypted,
  Base64-formatted output. Every buffer the library itself fills with a secret is one the GC
  never moves, so zeroing it erases the only managed copy:
  - Key material that outlives a call (each revealed DEK, the pipeline key and its base64 form)
    is allocated on the Pinned Object Heap (`ArrayUtility.AllocatePinned`).
  - Plaintext scratch buffers go on the stack up to `ArrayUtility.MaxStackBytes` (4 KiB, enough
    for any value `DefaultFormatProvider` accepts by default), and on the pinned heap beyond that.

  This is still a reduction of exposure, not a guarantee. Pinned memory can be paged to disk or
  captured in a crash dump. `AesGcm` keeps its own copy of the key in native crypto state, released
  when its session is disposed. Anything that reaches the library as a `string` (a configuration
  value, a `string` passed to `IDataProtector.Encrypt`) can never be zeroed at all. Hand secrets in
  as spans over buffers you own wherever you can, ideally ones on the stack or pinned heap too.
- **Safe under concurrency, without a lock on the hot path.** .NET's `AesGcm` is not thread-safe:
  on the OpenSSL backend (Linux) one instance owns a single cipher context that every call
  mutates, so two threads sharing it can encrypt one plaintext under the other's nonce - a nonce
  reuse that breaks GCM outright. A session therefore never shares an `AesGcm` between concurrent
  operations: each Encrypt/Decrypt takes one for its exclusive use from a small per-session pool
  and returns it after. The pool grows to the peak number of concurrent operations and no further;
  every pooled instance holds its own native copy of the key, all released when the session is
  disposed.
- **Built-in telemetry.** The key ring, data protectors, AES-GCM crypto provider, protected cache
  and encrypted configuration emit `System.Diagnostics.ActivitySource` activities
  (OpenTelemetry-compatible) with exceptions recorded on failure, and an opt-in sensitive-logging
  mode that emits operation metadata (never raw key/plaintext/ciphertext bytes). The key wrappers
  and key-file readers emit none (see [Diagnostics](#diagnostics)).

## Key rotation

The library has no rotation schedule of its own, by design. Each kind of key is rotated by an
event outside the running process:

| Key | Rotated when | How |
|---|---|---|
| Data encryption keys in key files | Every release | The release pipeline generates a fresh DEK, re-encrypts that release's configuration under it, wraps it into a new key file, and deploys the file. Nothing is carried over from the previous release. |
| Ephemeral keys (`WithEphemeralKey`) | Every 24 hours by default, and on every application restart | Generated in memory and never written anywhere. On a schedule the ring generates a fresh one and adds it as the next version, so every later `Encrypt` uses it. A restart discards them all and builds a new ring. |

A rotation adds the new key and keeps the one it replaced for a **retention** period (24 hours
by default), so values encrypted just before the rotation still decrypt. Once a superseded key
has been out of use for that long, the next rotation retires it: it is removed from the ring and
disposed, zeroing its DEK and stopping its background refresh, and anything still encrypted under
it fails with `KeyNotFoundException`. A ring therefore holds at most about `retention / interval`
superseded ephemeral keys, however long the process runs. Keys from key files are never retired.
Configure both on the builder, or in configuration through `HkdfGuardOptions`:

```csharp
builder.WithEphemeralKeyRotation(TimeSpan.FromHours(6));  // 1 hour to ~49 days; default 24 hours
builder.WithEphemeralKeyRetention(TimeSpan.FromHours(12)); // at least 1 minute; default 24 hours
builder.WithoutEphemeralKeyRotation();                    // keep the startup key until restart
builder.WithLogger(logger);                               // ILogger<KeyRing>: logs each rotation, retirement and failure
```

```jsonc
{ "EphemeralKeyRotationHours": 6 }          // 1-1193
{ "EphemeralKeyRetentionHours": 12 }        // at least 1; default 24
{ "DisableEphemeralKeyRotation": true }
```

Rotation can't be set below one hour. Each rotation generates a key through the KEK and starts a
background refresh loop for it, so rotating faster buys nothing and only loads the KMS.

A ring built only from key files never rotates on a schedule; its key-file version stays current.
If creating a new key fails, for example because the KEK is unreachable, the current key stays in
use, the failure is logged as an error, and the next interval tries again.

Rotation applies to everything that encrypts through the ring:

- **`IDataProtector`.** Each one from `KeyRing.CreateProtector` asks the ring for its current key
  on every `Encrypt`.
- **`ProtectedCache`.** It takes the ring (as `IKeyRing`) rather than a single key. Every
  `Add`/`AddOrUpdate` encrypts under the current key and records that key's version with the entry,
  and `Decrypt` uses the recorded version. Values cached before a rotation stay readable; values
  cached after it use the new key; `AddOrUpdate` of an existing name re-encrypts it under the new
  key. `AddKeyRingAsync` registers the ring as both `KeyRing` and `IKeyRing`, so a `ProtectedCache`
  registered in the same container picks it up.

```csharp
await using var ring = await new KeyRingBuilder() /* ... */ .WithEphemeralKey(100).BuildAsync();
var cache = new ProtectedCache(ring);
```

What this means in practice:

- **Release regularly.** A data encryption key lives exactly as long as its release, so release
  cadence is rotation cadence. If a release stays in production for a long time, schedule a
  redeployment, even one with no code changes, to rotate its key. Compliance rules about key age
  belong in the deployment process.
- **Expect the cache to be empty after a restart.** Everything encrypted under an ephemeral key
  becomes unreadable once the process restarts, so treat cached values as rebuildable. Never
  persist them. Rotating the cache key on every restart is intended.
- **A background refresh is not a rotation.** Every `KeyRefreshInterval` seconds a provider re-reveals
  the same key, to confirm the KEK is still reachable. It never changes which key encrypts; only a
  release, a restart, or a scheduled ephemeral rotation does that.
- **Size the retention to the cache's life.** A cached value is readable only while the key that
  encrypted it is in the ring: the current key, or a superseded one still within retention. With
  the defaults (24-hour rotation, 24-hour retention) a value written just before a rotation stays
  readable for at least 24 hours and at most 48. If values must live longer, raise the retention;
  if a key's exposure window matters more, lower it and treat older cached values as rebuildable.

## Architecture overview

```
                      +------------------------------------------+
                      | Hardware Security Module (TPM2 / Enclave) |
                      +------------------------------------------+
                                           |
                                  (Wraps / Unwraps)
                                           v
+---------------------+       +---------------------------------------+
| Native KMS Library  | <---> |   IKeyWrapper (NativeHkdfKeyWrapperV1, |
+---------------------+       |   resolved once per process by        |
                               |   NativeHost)                         |
                               +---------------------------------------+
                                           |
                                  (Reveals DEK)
                                           v
                              +---------------------------+
                              |       ICryptoProvider      |  <-- background timer refreshes
                              |    (AesGcmCryptoProvider)  |      + zeroes the outgoing session
                              +---------------------------+
                                           |
                                   (AEAD Encrypt/Decrypt)
                                           v
                              +---------------------------+
                              |     IDataEncryptionKey     |
                              |    (DataEncryptionKey)     |
                              +---------------------------+
                                           |
                               (Version Management / AAD)
                                           v
               +-------------------------------------------------------+
               |                       KeyRing                         |
               +-------------------------------------------------------+
                    /                      |                       \
                   v                       v                        v
     +------------------------+  +--------------------------+  +------------------------------+
     |     IDataProtector      |  |  IProtectedCache /        |  | IProtectedConfigurationRoot   |
     | (strings / char spans)  |  |  IProtectedReadOnlyCache  |  | (IConfigurationRoot wrapper)  |
     +------------------------+  +--------------------------+  +------------------------------+
```

Same shape as every other port in this workspace (the .NET repo drives the design, so Java/Go/
Node/Python mirror this layering, adding their own consumer branches as they catch up):

1. **KEK (Key Encryption Key)** - a hardware-backed key managed by the OS/TPM/Enclave, referenced
   only by a service name. The plaintext KEK never enters this process's memory.
2. **DEK (Data Encryption Key)** - a 256-bit symmetric key wrapped by the KEK. Can be persisted to
   disk or generated ephemerally in memory - both are a `DataEncryptionKey` around an
   `ICryptoProvider` minted via `ICryptoProviderFactory.CreateAsync`/`CreateEphemeralAsync` respectively.
3. **`ICryptoProvider`** - the active AEAD (AES-256-GCM) cipher session holding the unwrapped DEK.
   Automatically refreshes its session on a configured schedule (1-300 seconds), zeroing the
   outgoing one.
4. **`KeyRing`** - manages multiple versioned keys. Adding a new key version doesn't break
   decryption of data already protected under older versions.
5. **Formatted encrypted value** - the standardized `enc::v{version}::{base64}` string, handled by
   `IEncryptedFormatProvider`/`DefaultFormatProvider`. Values are capped at 4096 characters by
   default (about 3 KB of UTF-8 plaintext; configurable via the `DefaultFormatProvider` constructor):
   `Parse` rejects longer input before decoding it, and `Format` refuses to produce a value `Parse`
   would then reject, so an oversized secret fails when it's encrypted, not when it's read.

## Solution layout

| Project | Purpose |
|---|---|
| `HkdfGuard.Diagnostics` | Every library's telemetry, centralized: `HkdfGuardTelemetry` (one `ComponentTelemetry` per component - `ActivitySource`, `Meter`, `EnableSensitiveLogging`, `RecordException`, `LogSensitiveOperation`), `ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames` (OpenTelemetry semantic-convention-style names, e.g. `hkdfguard.cache.add`), `CacheMetrics`, and `HkdfGuardLoggerExtensions` (`[LoggerMessage]`-generated `ILogger` extensions). No dependency on any other project in this solution - the lowest layer, designed so its naming/shape can be ported identically into a Java/Node/Python/Go implementation. |
| `HkdfGuard.Abstractions` | Interfaces and pure data types only (`IKeyRing`, `IKeyWrapper`, `ICryptoProvider`, `ICryptoProviderFactory`, `IDataEncryptionKey`, `IDataProtector`, `IProtectedCache`/`IProtectedReadOnlyCache` - the latter with `DecryptAsync`/`GetMaxDecryptedLengthAsync` defaulting to its synchronous members, `IEncryptedFormatProvider`, `KeyTrackingValue`, `ArrayUtility`, `ProtectedCacheBase`). Depends only on `HkdfGuard.Diagnostics`. |
| `HkdfGuard.CryptoProvider.AesGcm256` | `AesGcmCryptoSession` (internal, key-bound at construction) wrapped directly by the public `AesGcmCryptoProvider` (an `ICryptoProvider` that reveals/refreshes it from an `IKeyWrapper` + wrapped bytes, and only ever holds one active session at a time; also exposes `GetEncryptedAllocationLength`/`GetDecryptedAllocationLength` for sizing buffers), minted via `AesGcmCryptoProviderFactory` (an `ICryptoProviderFactory`); plus `AesGcmPipelineDataProtector` (an `IPipelineDataProtector` over one in-memory key, for protecting values in a pipeline before a durable KEK exists - see below). Depends on `HkdfGuard.Abstractions`/`HkdfGuard.Diagnostics`; its `HkdfGuardTelemetry.CryptoProviderAesGcm256` component keeps its own independent `EnableSensitiveLogging` flag rather than sharing `Root`'s. |
| `HkdfGuard.KeyWrapping.V1` | `NativeHkdfKeyWrapperV1` (an `IKeyWrapper`, whose async methods complete synchronously) and `NativeHost`, which resolve and bind the current OS's native KMS library (Linux/.so, macOS/.dylib, Windows/.dll - see `Interop/`) to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `HkdfGuard.SecureFile` | `TrustedKeyFile.ReadAsync` and `KeyFileTrust` - the managed equivalent of the native library's `hkdfguard_open_file`, for key wrappers with no native library to read key files through (network KMS providers). Refuses a key file unless it, and every folder above it, is owned and modifiable only by the operating system's administrators and the principals a `KeyFileTrust` adds (Windows ACLs and final-path check; Linux/macOS ownership and mode bits, following only trusted symbolic links), and refuses contents that look like an unwrapped key. Depends on `HkdfGuard.Abstractions`. |
| `HkdfGuard.KeyWrapping.AwsKms` | `AwsKmsKeyWrapper` - an `IKeyWrapper` over one symmetric AWS KMS key (`Encrypt`/`Decrypt`/`GenerateDataKeyWithoutPlaintext`, the key pinned on every `Decrypt`, an optional encryption context bound as AAD), reading key files through `HkdfGuard.SecureFile`. Depends on `HkdfGuard.Abstractions`, `HkdfGuard.SecureFile` and `AWSSDK.KeyManagementService`. |
| `HkdfGuard.KeyWrapping.AzureKeyVault` | `AzureKeyVaultKeyWrapper` - an `IKeyWrapper` over two Azure Key Vault keys: an RSA key wraps each DEK (RSA-OAEP-256) and a separate EC P-256 key signs each wrapped DEK (ES256), verified before every unwrap, so only principals allowed to sign can create a key file it accepts. Both keys pinned by name, rotation-safe by version; an optional context bound into the signature; key files read through `HkdfGuard.SecureFile`. Depends on `HkdfGuard.Abstractions`, `HkdfGuard.SecureFile` and `Azure.Security.KeyVault.Keys`. |
| `HkdfGuard.KeyWrapping.GoogleKms` | `GoogleKmsKeyWrapper` - an `IKeyWrapper` over one symmetric Google Cloud KMS key (`Encrypt`/`Decrypt`, the key pinned on every `Decrypt`, a fixed HkdfGuard label and an optional context bound as AAD, CRC32C checksums on every request and response), reading key files through `HkdfGuard.SecureFile`. Depends on `HkdfGuard.Abstractions`, `HkdfGuard.SecureFile` and `Google.Cloud.Kms.V1`. |
| `HkdfGuard.DataEncryptionKey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `IDataProtector`/`DataProtector`, `DataEncryptionKey` (the `IDataEncryptionKey` over an `ICryptoProvider` - output sizing and telemetry; disposing it disposes its provider), and the default `enc::v{version}::{base64}` wire format. Depends on `HkdfGuard.Abstractions`/`HkdfGuard.Diagnostics`. |
| `HkdfGuard.Cache` | `ProtectedCache` (an `IProtectedCache` backed by an `IKeyRing` - encrypts under the ring's current key on Add/AddOrUpdate and records its version, reveals under that version on Decrypt, so it follows key rotation; nothing held as plaintext beyond a single call; each value is bound to its name as AAD, so a ciphertext under any other name fails authentication, and names match ignoring ASCII case only) `ProtectedCacheCollection` (aggregates multiple `IProtectedReadOnlyCache` sources behind one read-only surface, checked in registration order), and `RemoteSecretCache` (the shared base of the secret-store caches below: fetch-on-miss of one named secret through a `SecretValueSink` bound to that name - its whole value and, by `secret#key`, the keys it holds, all from one fetch - one fetch per secret at a time, missing values not remembered, exact or ASCII-case-insensitive name matching, and telemetry - a subclass supplies only `IsValidName` and `Fetch`) with `SecretJsonBody` (takes a secret out of a JSON response body into pinned memory and returns the body with it blanked, for an SDK to parse). |
| `HkdfGuard.Cache.AzureKeyVault` | `AzureKeyVaultSecretCache` - a `RemoteSecretCache` over one Azure Key Vault's secrets: on a miss it reads just the requested secret with `GetSecret`, taking the value out of the response body in pinned memory (a pipeline policy) so `SecretClient` never holds it as a string, encrypts it under the ring's current key bound to its name, and caches the ciphertext. Never lists the vault (needs only `get` on secrets); names Key Vault can't hold are reported missing without a call. Depends on `HkdfGuard.Cache` and `Azure.Security.KeyVault.Secrets`. |
| `HkdfGuard.Cache.AwsSecretsManager` | `AwsSecretsManagerSecretCache` - a `RemoteSecretCache` over AWS Secrets Manager: on a miss it reads just the requested secret with `GetSecretValue`, taking the value out of the response body in pinned memory (a pipeline handler ahead of unmarshalling) so the SDK never holds it as a string, encrypts it under the ring's current key bound to its name, and caches the ciphertext. Never lists secrets (needs only `secretsmanager:GetSecretValue`); names match exactly, as Secrets Manager's do; names it can't hold are reported missing without a call. Depends on `HkdfGuard.Cache` and `AWSSDK.SecretsManager`. |
| `HkdfGuard.Cache.GoogleSecretManager` | `GoogleSecretManagerSecretCache` - a `RemoteSecretCache` over one Google Cloud project's Secret Manager: on a miss it reads just the requested secret's latest version with `AccessSecretVersion`, checks its CRC32C and that the response names that secret, encrypts it under the ring's current key bound to its name, zeroes the payload and gRPC's pooled receive buffer, and caches the ciphertext. Never lists secrets (needs only `secretmanager.versions.access`); IDs match exactly, as Secret Manager's do; names it can't hold are reported missing without a call. Depends on `HkdfGuard.Cache` and `Google.Cloud.SecretManager.V1`. |
| `HkdfGuard.Cache.HashiCorpVault` | `HashiCorpVaultSecretCache` - a `RemoteSecretCache` over one HashiCorp Vault KV secrets engine (version 2 or 1): on a miss it reads just the requested secret's path (`path#key` picks the key) over Vault's HTTP API, reading the unbuffered response body into pinned memory so the value is never a string, encrypts it under the ring's current key bound to its name, and caches the ciphertext. Never lists secrets (the token needs only `read`); paths match exactly, as Vault's do; names that aren't a path and key are reported missing without a call. Authentication is left to an `IVaultTokenProvider` (`StaticVaultToken` for a token you hold). No dependency beyond `HkdfGuard.Cache`. |
| `HkdfGuard.EncryptedConfiguration` | `ProtectedConfigurationRoot` (an `IProtectedConfigurationRoot`) - wraps an `IConfigurationRoot`, revealing values formatted as protected secrets via a `KeyRing`; configuration itself only ever holds ciphertext, and `Decrypt` reads fresh from the underlying root every time so `Reload` takes effect immediately. Each value is bound to its own configuration key (`ProtectedConfigurationPurpose`), so a value copied to another key fails to decrypt. |
| `HkdfGuard.DependencyInjection` | `AddKeyRingAsync` - builds a `KeyRing` asynchronously at registration and registers it as a singleton in an `IServiceCollection`. |
| `HkdfGuard.Options` | `HkdfGuardOptions`/`HkdfGuardOptionsValidator`/`HkdfGuardOptionsExtensions.ApplyTo` - a plain-data mirror of `KeyRingBuilder`'s configuration surface (`ServiceName`, `KeyRefreshInterval`, `MaxRefreshFailures`/`FailOpenOnRefreshFailure`, key files, ephemeral keys), for binding a `KeyRing`'s identity/policy/key files from configuration. |
| `HkdfGuard.Diagnostics.Test`, `HkdfGuard.Abstractions.Test`, `HkdfGuard.CryptoProvider.AesGcm256.Test`, `HkdfGuard.KeyWrapping.V1.Test`, `HkdfGuard.SecureFile.Test`, `HkdfGuard.KeyWrapping.AwsKms.Test`, `HkdfGuard.KeyWrapping.AzureKeyVault.Test`, `HkdfGuard.KeyWrapping.GoogleKms.Test`, `HkdfGuard.DataEncryptionKey.Test`, `HkdfGuard.Cache.Test`, `HkdfGuard.Cache.AzureKeyVault.Test`, `HkdfGuard.Cache.AwsSecretsManager.Test`, `HkdfGuard.Cache.GoogleSecretManager.Test`, `HkdfGuard.Cache.HashiCorpVault.Test`, `HkdfGuard.EncryptedConfiguration.Test`, `HkdfGuard.DependencyInjection.Test`, `HkdfGuard.Options.Test` | xUnit test suites, maintained at full line/branch coverage for their respective projects. |

Requires **.NET 10** (`net10.0`).

## Getting started

### 1. Wrap or reveal a DEK

`NativeHkdfKeyWrapperV1` is an `IKeyWrapper` bound to whichever native KMS library matches the
current OS (resolved once per process by `NativeHost`), identified only by a service name. Since
`Decrypt` takes the wrapped payload as an explicit argument rather than one bound at construction,
a single instance freely handles both directions, and any number of different wrapped payloads
sharing that service name:

```csharp
var wrapper = new NativeHkdfKeyWrapperV1("my.service");

// Generate a fresh 32-byte DEK inside the native library and get back only its wrapped form:
byte[] wrapped = new byte[512]; // native library's own payload format/size
int written = await wrapper.GenerateAndWrapAsync(wrapped);

// Later, reveal the DEK from that wrapped payload for the same service:
byte[] dek = new byte[32];
await wrapper.UnwrapAsync(wrapped.AsMemory(0, written), dek);
// ... use it, then CryptographicOperations.ZeroMemory(dek)
```

`WrapAsync` wraps a DEK you already hold. Failures surface as `CryptographicException`. The native
ABI has no concept of Additional Authenticated Data, so `IKeyWrapper` has no AAD parameter.

No native library creates a KEK during wrap or unwrap. Provision each service once with
`hkdfguard provision --service-name <name>` (elevated on Windows), or every call fails.
A service name is 1-128 ASCII letters, digits or dots, never starts with a dot and never contains
`..`, so `my.service` rather than `my-service`. `ServiceNames` holds the rule. `NativeHkdfKeyWrapperV1`,
`KeyRingBuilder.WithServiceName` and the options validator all enforce it, so a bad name fails
with a message saying which rule it broke, before any native call.

Where each platform's library comes from:

| Platform | Library | How it is found |
|---|---|---|
| Windows | `HkdfGuard.dll` | Installed to `%ProgramFiles%\HkdfGuard\v1` and loaded only from there. Not shipped in the package. |
| macOS | `libhkdfguard.dylib` | Installed system-wide to `/Library/Application Support/HkdfGuard/v1`, or per user to `~/.hkdfguard/v1`, and loaded only from there. Not shipped in the package. Requires Apple silicon and macOS 13 or later, with an arm64 .NET runtime (not an x64 one under Rosetta). |
| Linux | `libhkdfguard.so.1` | Installed by the `libhkdfguard1` package (`hkdfguard-libs` on RPM distributions) to `/usr/lib/<multiarch>` or `/usr/lib64`, and loaded only from there. Not shipped in the package. x64 and arm64. |

The NuGet package contains no native library. Each one is distributed and installed separately,
together with its provisioning tool, `hkdfguard`.

The library sees every DEK, so it is never located by a search path.

On **Windows**, before mapping it, `WindowsNativeLibraryLoader` requires all of the following:
- No folder on its path is a symlink or junction.
- The file and every parent folder below the drive root are owned and writable only by SYSTEM,
  Administrators or TrustedInstaller.
- The drive root has a trusted owner and lets no one else rename or delete a folder directly
  beneath it (delete-child, or the right to change its ACL or owner). Creating new folders there,
  which a default `C:\` allows every user, is permitted.
- The file has a valid, trusted Authenticode signature from the expected publisher. The chain
  WinVerifyTrust validated must end at the pinned Azure Artifact Signing root (Microsoft Identity
  Verification Root Certificate Authority 2020, matched by SHA-256, not by name). The signing
  certificate must carry the Code Signing EKU and the EKU of HkdfGuard's own Artifact Signing
  certificate profile. A matching subject from any other trusted root is refused, including a root
  a user added to their own certificate store. The leaf and intermediate certificates are not
  pinned, because Artifact Signing reissues them often. This verification makes no network calls.
- No certificate in the signer's chain has been revoked. Checked once per process, after every
  other check has passed, by a second verification that may fetch revocation information over the
  network. Only a definite "revoked" refuses the load; if revocation servers can't be reached, or
  give no answer, the library loads, so a host with no network still starts. On a host whose
  network silently drops traffic rather than refusing it, the first load can stall once until the
  revocation lookup times out.
- The signed PE header marks the file as a DLL for the process's architecture. The publisher's
  other signed binaries, such as `hkdfguard.exe`, pass the signature checks, so
  this check is what refuses one renamed into place.
- Its version resource - also covered by the signature - is at least `MinimumLibraryVersion`
  (0.9.0). An older release, or one with no version resource, is refused even though it is
  genuinely signed.

Its dependencies are then loaded from System32 only, and after loading, the module Windows mapped
must be the verified file (`GetModuleFileNameW`), so neither a same-named DLL already in the process
nor loader redirection can stand in for it. Any failed check throws, with no fallback, so a DLL
planted on `PATH` or beside the application is never loaded.

On **macOS**, `MacOsNativeLibraryLoader` uses the system install whenever it exists, and the
per-user install only when there is no system install. Anything running as the user can write to
the user's home, so a per-user file must never be able to override a root-owned system one. The
home is the effective user's entry in the account database (`getpwuid_r`), never the `HOME`
environment variable, which whoever starts the process could point anywhere; with no usable entry,
only the system install is considered. If the
system install exists but fails a check, loading fails instead of falling back - and so does a
system install that merely can't be examined (say, a directory this process may not read): only
"nothing is there" counts as "not installed". Before loading, it requires all of the following:
- No component of the path, up to `/`, is a symbolic link.
- Every component of a system install is owned by root; of a user install, by root or the current
  user.
- No component is writable by anyone but its owner. The one exception is the system directories
  above an install (`/`, `/Library`, `/Library/Application Support`, `/Users`), which may also be
  writable by the `wheel` or `admin` group when root owns them, as `/Library/Application Support`
  often is. The install's own directories and the library file never are.
- The file's code signature is valid, carries the identifier `libhkdfguard`, and was made with
  a Developer ID Application certificate issued through Apple's CA to the HkdfGuard team
  (`MFW3T8R8J3`). A development-signed build, or any other binary the team signs, is refused.
- The library's own version - its `LC_ID_DYLIB` current version, in the Mach-O header the
  signature covers - is at least `MinimumLibraryVersion` (0.9.0). An older release is refused even
  though it is genuinely signed, so it can't be put in place of a current one.

Certificate revocation is not checked on macOS. Apple's code-signing check can be told to require
it, but then a host that can't reach Apple's servers couldn't load the library, turning a network
outage into a service outage. What stands in for it: the signature must come from HkdfGuard's
Developer ID and team, the system install can only be written by an administrator, and the minimum
version refuses older genuine releases. The accepted risk is a stolen HkdfGuard signing
certificate: whoever holds it, and can also write an install location (an administrator for the
system install, the same user for a per-user one), could sign and plant a library of their own,
whatever version it claims. The answer to such a compromise is Apple revoking the certificate and a
new release; until consumers update, the system install's admin-only location is the barrier, so
prefer it to a per-user install in production.

`dlopen` of an absolute path does not load exactly that path: dyld first looks for the file's
name in every `DYLD_LIBRARY_PATH` directory, and the `dotnet` host honours `DYLD_*` variables
despite its hardened runtime. So the loader refuses, before loading, if a `DYLD_LIBRARY_PATH`
directory contains a `libhkdfguard.dylib`; and after loading it asks dyld which file it really
mapped, unloading and refusing anything but the verified path. The library's own dependencies are
absolute system paths and need no such check.

The loader also refuses while `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`,
`DYLD_VERSIONED_LIBRARY_PATH`, `DYLD_VERSIONED_FRAMEWORK_PATH` or `DYLD_IMAGE_SUFFIX` is set: each
makes dyld inject code or substitute a library the native library calls with every DEK. These
checks catch a misconfigured environment, not someone who controls it: dyld acts on the variables
when the process starts, so injected code has already run, and can hide, by the time the loader
looks. The real protection is a host signed with the Hardened Runtime, which makes dyld ignore them.

On **Linux**, `LinuxNativeLibraryLoader` uses the package's file in the Debian multiarch directory
(`/usr/lib/x86_64-linux-gnu` or `/usr/lib/aarch64-linux-gnu`) if it is there, otherwise the one in
`/usr/lib64`. Only "nothing is there" moves on; a location that can't be examined is refused.
Before loading, it requires all of the following:
- Every directory on the path, every symbolic link followed, and the file itself are owned by root,
  and no directory or file is writable by its group or by others. Links are followed one component
  at a time and each target is checked where it lies, so `/lib -> usr/lib` passes and a link into a
  user's directory does not.
- The dynamic linker's environment is checked. `dlopen` of an absolute path is
  never searched for, but the library's dependencies are found by name - and `libtss2-esys`
  receives every ECDH shared secret. So every `LD_LIBRARY_PATH` directory, and every path-named
  `LD_PRELOAD` or `LD_AUDIT` object, must pass the same path checks, and none may be relative,
  empty (the working directory) or use `$ORIGIN`-style tokens. Both the environment the process
  started with (`/proc/self/environ`) and the current one are checked.
  This check catches a misconfigured environment. It can't stop someone who controls the
  service's environment: whatever `LD_PRELOAD` or `LD_AUDIT` loads runs when the process starts,
  before the check, and can hide from it. Protect the service's environment (its unit file,
  container spec or launch configuration) as carefully as its binaries.
- The process's own dynamic linker (its `PT_INTERP`, which must pass the same path checks) is
  asked in list mode (`ld.so --list`, what `ldd` uses), under the `LD_LIBRARY_PATH` and
  `LD_PRELOAD` the process started with and nothing else, where it would find every library
  `libhkdfguard.so.1` pulls in. Each must pass the same path checks, so a dependency found
  somewhere writable is refused before any of its code runs; a dependency it can't find, or output
  it can't parse, refuses the load too.

After loading, `dladdr` must place the library's export in the verified file, and every object in
its dependency closure, read from each file's `DT_NEEDED` entries, must be bound to a file that
passes the path checks. That catches what list mode can't see: a dependency name the process had
already bound to some other object before the load; the library is then unloaded and the load
refused. Two things are outside
the loader's reach: the TPM transport module tpm2-tss loads at the first TPM call, which only the
environment check covers, and the .NET runtime's own injection points (startup hooks, CLR
profilers), which need a protected service environment on every platform.

Linux has no platform code signature, and the loader does not pin the file's content. Verify a
native Linux release's Sigstore build-provenance attestation (with `cosign` or
`gh attestation verify`) before installing its package; the loader then relies on path integrity.

### Process hardening

DEKs pass through your process's memory, so a crash dump, or another process of the same user
attaching a debugger or reading that memory, could recover them. `NativeProcessHardening.Apply()`
calls the native library's `hkdfguard_harden_process_with_flags` to close that off, on every
platform:

| Platform | What it does |
|---|---|
| Windows | Crash reports leave out the heap, and the process's and its threads' access lists are replaced so only SYSTEM can read or write its memory, inject threads or duplicate its handles. Its own account keeps only query, synchronize and terminate. |
| Linux | Core dumps off (hard limit included), and the process marked non-dumpable, which also stops ptrace and `/proc/<pid>/mem` access by the same user. |
| macOS | Core dumps off and debugger attachment denied. Whether code can be injected depends on the host executable's code signature, which the library checks but can't change. |

Neither the native library nor any machine policy does this for you: it changes process-wide
state your application owns, so it is opt-in. Call it once, early in startup - before starting
worker threads on Windows, and after any privilege drop on Linux:

```csharp
NativeProcessHardening.Apply();   // throws InvalidOperationException if it fails: don't start
```

Debuggers, `dotnet-dump` and crash dumps stop working for the process. It is a same-user barrier:
it does not stop administrators, root, SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or the kernel,
and it does not keep memory out of swap, the page file or hibernation files.

`NativeProcessHardening.Apply(ProcessHardeningOptions.RequireProtectedSignature)` is the strict
form the native command-line tools use: it fails unless no other process of the same user can
debug or inject into this one.

- **Windows:** it also closes threads started later, and everything else the process creates
  afterwards without its own security descriptor (child processes, named pipes, named events), to
  its own account. Use it in a service that shares no objects with other processes by name.
- **macOS:** it fails unless the host executable is signed with the Hardened Runtime and without
  the `get-task-allow` or `DYLD_*` entitlements, so unsigned hosts such as `dotnet` itself can't
  use it. Without it, a weak signature is only logged.
- **Linux:** it adds nothing; the plain call already guarantees it.

**.NET on Windows:** the plain call closes the threads that exist when it runs, and threads started
later keep the default access, which lets other processes of the same user read and change their
registers. A .NET application can't call it "before starting threads": the runtime starts threads of
its own before `Main` runs (the finalizer thread, for one), and keeps adding more whenever it needs
them - thread-pool workers for `async` I/O, timers and `Task.Run`. Calling it first thing in `Main`
covers the threads that exist then, not the ones the runtime adds later, so **use
`RequireProtectedSignature` for a Windows service**: it closes later threads too.

### Wrapping under AWS KMS instead

`AwsKmsKeyWrapper` (package `HkdfGuard.KeyWrapping.AwsKms`) is an `IKeyWrapper` over one symmetric
AWS KMS key. Use it in place of `NativeHkdfKeyWrapperV1` wherever a wrapper is taken. Every call is
a KMS request, authorized by the process's IAM credentials and recorded in CloudTrail:

```csharp
using var kms = new AmazonKeyManagementServiceClient(); // default credential and region chain
var wrapper = new AwsKmsKeyWrapper(kms,
    "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    new Dictionary<string, string> { ["purpose"] = "my.service" });
```

- `GenerateAndWrapAsync` calls `GenerateDataKeyWithoutPlaintext` for an AES-256 key, so the
  plaintext DEK never leaves KMS on that call. `WrapAsync` calls `Encrypt` and `UnwrapAsync` calls `Decrypt`.
- The key is pinned on every `Decrypt`. A symmetric ciphertext names its own key, and without the pin
  a substituted key file wrapped under any other key the principal may use would still be revealed.
  Prefer a key ARN to an alias: `Decrypt` resolves an alias when it is called, so re-pointing the
  alias makes DEKs wrapped under the old key unreadable. KMS's automatic key rotation keeps the
  ARN and needs nothing here.
- The optional encryption context is KMS's AAD. It is bound into every wrapped DEK, required again
  to reveal it, and can be required by the key policy (`kms:EncryptionContext:purpose`). CloudTrail
  logs it in plaintext, so it must never hold a secret.
- Failures surface as `CryptographicException`, naming KMS's error code (for example
  `AccessDeniedException` or `InvalidCiphertextException`), with the AWS exception as the inner
  exception. A failed unwrap zeroes the caller's buffer.
- Key files are read only from where no untrusted account could have written or replaced them, by
  the native library's rules, checked in managed code: on Windows, a local fixed drive, reached
  through no link, junction or substituted drive, with the file and every folder above it owned and
  modifiable only by SYSTEM, Administrators or TrustedInstaller; on Linux and macOS, the file and
  every directory above it owned by root and writable by no one else, following only root-owned
  links. A `KeyFileTrust` passed to the constructor adds the deployment's own account or group. A
  file that looks like an unwrapped key is refused too. A KMS ciphertext is about 184 bytes, well
  inside `WrappedKeyLimits.MaxBytes`.
- The principal needs `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKeyWithoutPlaintext` on the key.
  A process that only reads existing key files needs only `kms:Decrypt`.

[Wrap keys with AWS KMS](docs/how-to/use-aws-kms.md) walks through creating the key, the IAM
permissions for each role, credentials, and creating key files.

### Wrapping under Azure Key Vault instead

`AzureKeyVaultKeyWrapper` (package `HkdfGuard.KeyWrapping.AzureKeyVault`) wraps each DEK under an
RSA key in Key Vault and signs it with a separate EC P-256 key; unwrap verifies the signature
first. RSA wrapping needs only the public key, so without the signature anyone could create a key
file holding a DEK they chose; with it, only principals allowed to sign can:

```csharp
var wrapper = new AzureKeyVaultKeyWrapper(
    new Uri("https://myvault.vault.azure.net/keys/myapp-wrap"),
    new Uri("https://myvault.vault.azure.net/keys/myapp-sign"),
    new DefaultAzureCredential(),
    context: "my.service");
```

[Wrap keys with Azure Key Vault](docs/how-to/use-azure-key-vault.md) covers creating both keys,
the role for each identity, and rotation.

### Wrapping under Google Cloud KMS instead

`GoogleKmsKeyWrapper` (package `HkdfGuard.KeyWrapping.GoogleKms`) is an `IKeyWrapper` over one
symmetric Cloud KMS key, pinned on every `Decrypt`. Each wrapped DEK is bound, as AAD, to a fixed
HkdfGuard label and an optional context, and every request and response is checked with CRC32C.
The client signs in with Application Default Credentials:

```csharp
var kms = await KeyManagementServiceClient.CreateAsync();
var wrapper = new GoogleKmsKeyWrapper(kms,
    "projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
    context: "my.service");
```

As with AWS KMS, any principal allowed to encrypt under the key can create a key file the wrapper
accepts: give the application `roles/cloudkms.cryptoKeyDecrypter` only.
[Wrap keys with Google Cloud KMS](docs/how-to/use-google-kms.md) covers creating the key, the role
for each identity, and rotation.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation
policy, a shared `IKeyWrapper` and an `ICryptoProviderFactory`, and any number of wrapped-DEK
files - one per version - then reads each file, mints its own `ICryptoProvider` (via
`ICryptoProviderFactory.CreateAsync`), and wires it into a `DataEncryptionKey`.
`WithEphemeralKey` registers a version whose key is instead generated fresh at build time (via
`ICryptoProviderFactory.CreateEphemeralAsync`) and never written to disk - it shares the same
`IKeyWrapper`/`ICryptoProviderFactory`, so no extra configuration is needed for it. Range checks
happen in the setters (`WithServiceName`, `WithKeyRefreshInterval`, `WithMaxRefreshFailures`); `BuildAsync` checks that a key
wrapper, a crypto provider factory, a key refresh interval (there's no default), and at least one key
were configured. `BuildAsync` reads every key file through the key wrapper
(`IKeyWrapper.ReadKeyFileAsync`). `NativeHkdfKeyWrapperV1` reads it through the native library's
`hkdfguard_open_file`, which refuses a key file another account could have written or replaced (a
link, junction or short name in its path, or loose ownership or permissions), and one that holds
what looks like an unwrapped key: a refusal is a `FileNotFoundException`,
`UnauthorizedAccessException` or `InvalidDataException` naming the native status (see
[the CLI reference](docs/reference/cli.md#status-codes)). There is no fallback reader: every key
wrapper must implement `ReadKeyFileAsync` itself, refusing a file that an untrusted account could
have written or replaced, since whoever can replace a key file chooses the key new data is
encrypted under. A wrapped key is at most `WrappedKeyLimits.MaxBytes` (512) bytes, which leaves
room for larger keys and extra fingerprinting beyond today's 125-byte macOS payload; raising that
one constant also resizes the buffer an ephemeral key is generated into. If anything fails or is cancelled partway through, every provider
it already created is disposed.

Building is asynchronous only: `BuildAsync` reads the key files and reveals every key through the
key wrapper without blocking a thread, which matters once the key wrapper is network-backed (a
cloud KMS). There is no synchronous `Build()` - await it at startup.

```csharp
var ring = await new KeyRingBuilder()
    .WithServiceName("my.service")
    .WithKeyRefreshInterval(60)   // seconds, 1-300 - required before building
    .WithMaxRefreshFailures(5) // optional: default 3; WithFailOpenOnRefreshFailure() opts out of failing closed
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("my.service"))
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory(logger)) // logger: ILogger<AesGcmCryptoProvider>
    .WithKeyFile(version: 1, pathToFile: "/path/to/wrapped-dek-v1.bin")
    .WithEphemeralKey(version: 2)
    .BuildAsync(cancellationToken);
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.CurrentVersion` - existing ciphertext tagged with older versions continues
to decrypt correctly as long as those files stay registered.

The ring owns its keys: disposing it disposes every key, which stops each provider's background
refresh and zeroes its DEK. Prefer `await ring.DisposeAsync()` (or `await using`), which awaits each
provider's refresh loop instead of blocking on it; `Dispose()` remains for `IDisposable` callers.

Or via `HkdfGuard.DependencyInjection`'s `AddKeyRingAsync`. The DI container can't construct a
service asynchronously, so the ring is built eagerly, at registration - before the container
exists - and then registered as a singleton. If a `KeyRing` is already registered, the call does
nothing and the configure delegate is never run, so no keys are revealed for a ring that would be
thrown away. Once the ring has been resolved, the container owns it and disposes it at shutdown:

```csharp
await builder.Services.AddKeyRingAsync(ring => ring
    .WithServiceName("my.service")
    .WithKeyRefreshInterval(60)
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("my.service"))
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyFile(version: 1, pathToFile: "/path/to/wrapped-dek-v1.bin"));
```

### 3. Encrypt and decrypt

```csharp
IDataProtector protector = ring.CreateProtector("cookie-auth"); // "cookie-auth" becomes this protector's AAD

string encrypted = protector.Encrypt("secret value".AsSpan());
// e.g. "enc::v1::AbCdEf..."

Span<char> buffer = new char[protector.GetMaxDecryptedLength(encrypted.AsSpan())];
int written = protector.Decrypt(encrypted.AsSpan(), buffer);
string decrypted = new string(buffer[..written]);
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.
The name must be non-empty.
An empty value is a legitimate input here: it produces an authenticated, empty message. The one
place empty values are refused is `IProtectedCache.Add`/`AddOrUpdate`, because its `Decrypt`
reports a missing name as 0 bytes and an empty value would be indistinguishable from no value.

### Ephemeral, in-memory-only keys

For runtime encryption that doesn't need a durable, file-backed key at all,
`ICryptoProviderFactory.CreateEphemeralAsync` generates and wraps a fresh DEK once via
`IKeyWrapper.GenerateAndWrapAsync` - the plaintext DEK never crosses that call's return value, and
nothing here is ever written to or read from a file. The key - and everything encrypted under
it - lasts only as long as the process. Wrap the resulting `ICryptoProvider` in a
`DataEncryptionKey`, exactly as for a file-backed key (or just call
`KeyRingBuilder.WithEphemeralKey` - see above, which does exactly this):

```csharp
var provider = await new AesGcmCryptoProviderFactory().CreateEphemeralAsync(
    new NativeHkdfKeyWrapperV1("my.service"), expirySeconds: 60);
await using var ephemeralKey = new DataEncryptionKey(provider);
```

`DataEncryptionKey` shares its name with its namespace, so code that itself lives inside another
`HkdfGuard.*` namespace must write it fully qualified (`HkdfGuard.DataEncryptionKey.DataEncryptionKey`);
application code outside `HkdfGuard.*` can use the short name with
`using HkdfGuard.DataEncryptionKey;`.

### Caching Azure Key Vault secrets

`AzureKeyVaultSecretCache` (package `HkdfGuard.Cache.AzureKeyVault`) is an
`IProtectedReadOnlyCache` over the secrets in one vault. Nothing is fetched up front: the first
`Decrypt` or `TryGetMaxDecryptedLength` for a name reads that one secret with `GetSecret`,
encrypts it under the ring's current key, and caches only the ciphertext; later lookups never call
Key Vault. It never lists the vault, so the application needs only the **Key Vault Secrets User**
role (`get` on secrets), never `list`:

```csharp
var secrets = new AzureKeyVaultSecretCache(
    new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential(), ring);

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("Db-Password", buffer); // 0 if the secret doesn't exist
```

A missing (404) or empty secret returns 0 and is looked up again next time; any other failure
(access denied, a disabled secret, the vault unreachable) throws the Azure exception. A name Key
Vault can't hold (anything but 1-127 ASCII letters, digits and hyphens, e.g.
`ConnectionStrings:Admin`) returns 0 without a call, so the cache can go last in a
`ProtectedCacheCollection` behind other sources. A cached value isn't refreshed: a new secret
version is picked up by a new cache instance.

**A secret never becomes a `string`.** Every SDK here would hand a secret over as a `string` (Key
Vault, Secrets Manager) or leave it in a pooled buffer (gRPC, HttpClient's buffered responses),
none of which can be zeroed. So each cache makes its own client and takes the value out below the
SDK: Key Vault and Secrets Manager responses are read off the network into pinned memory by a
pipeline policy or handler, the value is passed to the cache as bytes (`SecretJsonBody`), and the
SDK parses a copy of the response with the value blanked; Vault's unbuffered response is read the
same way, with no SDK above it; Google's protobuf payload is encrypted from the bytes it was deserialized into,
and both those bytes and gRPC's pooled receive buffer are zeroed. Every buffer that held a value is
zeroed once it is encrypted. What no library above the HTTP stack can reach are that stack's own
buffers (TLS decryption, socket reads). For the same reason, the Key Vault cache refuses client
options that log response content.

To use your own transport, retries or timeouts, pass them in the options each cache takes
(`SecretClientOptions`, `AmazonSecretsManagerConfig`, or a gRPC `CallInvoker`) rather than a
ready-made client. The Key Vault cache adds its capture policy to the `SecretClientOptions`
instance you pass, since the SDK can't copy one. The policy acts only on the cache's own fetches,
so another `SecretClient` built from the same options is unaffected; still, prefer a fresh options
instance per cache, as each cache built from it adds the policy again.

### Caching AWS Secrets Manager secrets

`AwsSecretsManagerSecretCache` (package `HkdfGuard.Cache.AwsSecretsManager`) does the same over
AWS Secrets Manager: the first lookup of a name calls `GetSecretValue` for that one secret
(`AWSCURRENT`), and only the ciphertext is cached. It never calls `ListSecrets` or
`BatchGetSecretValue`, so the application needs only `secretsmanager:GetSecretValue` on the
secrets it reads (plus `kms:Decrypt` on a customer managed key that encrypts them):

```csharp
using var secrets = new AwsSecretsManagerSecretCache(ring); // region and credentials from the SDK's defaults

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("prod/Db-Password", buffer); // 0 if the secret doesn't exist
```

Names are matched exactly, as Secrets Manager matches them, so `prod/Db` and `prod/db` are separate
secrets and separate entries. Look secrets up by name, not ARN: anything but 1-512 ASCII letters,
digits and `/_+=.@-` returns 0 without a call. A `SecretString` is cached as UTF-8 bytes and a
`SecretBinary` as its bytes. The AWS SDK is async-only and the cache interface is synchronous, so a
first lookup blocks until AWS answers; set timeouts on the `AmazonSecretsManagerConfig` the cache
takes. The cache owns its client, so dispose it. Missing, empty, failure and refresh behavior are
as for Key Vault above.

### Caching Google Cloud Secret Manager secrets

`GoogleSecretManagerSecretCache` (package `HkdfGuard.Cache.GoogleSecretManager`) does the same over
one project's Secret Manager: the first lookup of a name calls `AccessSecretVersion` for that one
secret's `latest` version, and only the ciphertext is cached. It never lists secrets or versions,
so the application needs only the **Secret Manager Secret Accessor** role
(`secretmanager.versions.access`):

```csharp
using var secrets = GoogleSecretManagerSecretCache.Create(
    "my-project", await GoogleCredential.GetApplicationDefaultAsync(), ring);

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("Db-Password", buffer); // 0 if the secret doesn't exist
```

Secret IDs are matched exactly, as Secret Manager matches them, so `Db` and `db` are separate
secrets and separate entries; anything but 1-255 ASCII letters, digits, hyphens and underscores
returns 0 without a call. The payload is cached as its bytes. `Create` makes and owns a channel;
to use your own, pass its `CallInvoker` to the constructor instead. A payload whose
CRC32C doesn't match the checksum Google returns, or a response naming a different secret, is
refused with a `CryptographicException`. A secret that doesn't exist or has no versions returns 0;
a disabled or destroyed latest version, like any other failure, throws the gRPC `RpcException`.
Refresh behavior is as for Key Vault above.

### Caching HashiCorp Vault secrets

`HashiCorpVaultSecretCache` (package `HkdfGuard.Cache.HashiCorpVault`) does the same over one KV
secrets engine: the first lookup of a name reads that one secret's path (for KV version 2, its
latest version), and only the ciphertext is cached. It never lists, so the token's policy needs
only `read` on the paths it reads. A Vault secret holds several keys, so a name is the secret's
path with the key after `#`, and a name without one reads `DefaultKey` (`value` unless set). One
read caches every key the secret holds (see [Secrets holding several keys](#secrets-holding-several-keys)):

```csharp
var tokenProtector = ring.CreateProtector(HashiCorpVaultSecretCache.TokenPurpose);
using var secrets = new HashiCorpVaultSecretCache(
    new Uri("https://vault.example.com:8200"),
    StaticVaultToken.Protect(tokenProtector, Environment.GetEnvironmentVariable("VAULT_TOKEN")), // held encrypted
    tokenProtector,
    ring,
    new HashiCorpVaultSecretCacheOptions { MountPath = "secret" }); // KV version 2 unless KvVersion says 1

Span<char> buffer = stackalloc char[256];
int written = secrets.Decrypt("myapp/db#password", buffer); // 0 if there's no such secret or key
```

Authentication isn't the cache's: every fetch asks its `IVaultTokenProvider` for a token, so a
provider can log in (AppRole, Kubernetes, a certificate) and renew or replace its token however it
likes. The provider hands the token over protected - encrypted by the token protector, a protector
on the key ring created with `HashiCorpVaultSecretCache.TokenPurpose`, as
`tokenProtector.Encrypt(token)` - and a fetch given a token that isn't protected so (plain text,
another purpose, another ring, a key version the ring no longer holds) fails with
`InvalidOperationException`, without calling Vault or quoting what it was given. The cache decrypts
the token only as each request is built, into stack or pinned memory, then into the one string the
`X-Vault-Token` header needs - an HTTP header can only be a string - and zeroes that string's
memory as soon as the request has been sent, so the token's plaintext lives for one request.
What's beyond reach is the HTTP stack's own write and TLS buffers. `StaticVaultToken.Protect`
holds a token you already hold only in that protected form; nothing renews it, so once it expires
every fetch fails with 403. The address must be https except on loopback, and the cache's own HTTP
handler follows no redirects, which would carry the token elsewhere; to trust a private CA or use a
proxy, pass a handler in the options. A `SocketsHttpHandler` or `HttpClientHandler` follows
redirects by default, and .NET drops only the `Authorization` header when it does, so the cache
refuses one with `AllowAutoRedirect` still on - set it to `false`, or set the cache's
`AllowRedirects` if every redirect target may see the token. `Namespace` sets
`X-Vault-Namespace` for Vault Enterprise.

Paths match exactly, as Vault's do. A name whose path segments aren't ASCII letters, digits, `-`,
`_` and `.` - or that holds a `.`/`..` segment, e.g. `ConnectionStrings:Admin` - returns 0
without a call. A secret that doesn't exist (404 with no errors), whose latest version is deleted
or destroyed, or that lacks the key or holds no value there that is cached, returns 0 and is
looked up again next time. Any other answer (403, a 404 naming an error such as a missing
mount, a sealed Vault) throws an `HttpRequestException` carrying Vault's status and errors, never
the token. A request that fails transiently - no answer (connection refused or reset, DNS), a
connection lost mid-response, an attempt that took longer than `Timeout`, or 429 or a 5xx other than
501 (Vault answers 503 while sealed or electing a leader) - is retried `RetryCount` times (3 to 10,
default 3). The first retry waits `RetryDelay` (default 200 ms), each after it twice as long, up to
10 seconds, and every wait adds a random 0-100 ms, so many devices reconnecting at once after an
outage don't retry in lockstep. Anything else, the token provider's failures and your own
cancellation included, isn't retried. Dispose the cache to release its connections. Refresh behavior is as for Key Vault above.

### Secrets holding several keys

A secret often holds a set of credentials rather than one: an AWS Secrets Manager key/value
secret (stored as a JSON object in its `SecretString`), a JSON object kept in a Key Vault secret or
a Google payload by convention, or any Vault KV secret. Every cache reads one key of such a secret
by name, as `secret#key`:

```csharp
// The AWS secret "prod/app" holds {"api-credential-21":"...","test-credential-1":"...","port":5432}.
int written = secrets.Decrypt("prod/app#api-credential-21", buffer);
written = secrets.Decrypt("prod/app#port", buffer);  // "5432"
written = secrets.Decrypt("prod/app", buffer);       // the whole JSON text, as before
```

The first lookup of any of a secret's keys fetches the secret once and caches its whole value and
every key it holds, each encrypted on its own and bound to its own name; the rest are served from
the cache, and concurrent lookups of different keys share that one fetch. Each value is unescaped
into pinned memory and zeroed once encrypted, like a whole value - never a string. A string member
is cached as its UTF-8 bytes; a number, `true` or `false` as its JSON text; `null`, an object, an
array, an empty string, or a member whose name isn't a key (1-256 printable ASCII characters other
than space, `!` and `#`) is left out. A value that isn't exactly one JSON object (plain text, an
array, malformed JSON) is cached whole only; an object naming a member twice is refused with
`InvalidDataException`. An AWS `SecretBinary` is never split.

Keys match exactly, even in Key Vault, whose secret names ignore case: `App-Login#user` and
`app-login#user` are the same key, `App-Login#User` is another. A key the secret doesn't hold
returns 0 and costs a fetch each time it is asked for. A later fetch of a secret adds keys that
weren't cached yet but never replaces one that was; as for whole values, a new secret version is
picked up by a new cache instance.

### Reading asynchronously

Every `IProtectedReadOnlyCache` also has `DecryptAsync` (into a `Memory<byte>` or `Memory<char>`)
and `GetMaxDecryptedLengthAsync`. On a secret-store cache they fetch a missing secret without
blocking a thread - with `GetSecretAsync`, `GetSecretValueAsync`, `AccessSecretVersionAsync`, or
Vault's HTTP API, the response body read asynchronously into the same pinned memory - where
`Decrypt` and `TryGetMaxDecryptedLength` block until the store answers. In ASP.NET Core and other
async code, prefer them for anything that may miss:

```csharp
var max = await secrets.GetMaxDecryptedLengthAsync("prod/app#api-key", cancellationToken); // 0 if missing
var buffer = ArrayUtility.AllocatePinned<char>(max);
try
{
    var written = await secrets.DecryptAsync("prod/app#api-key", buffer.AsMemory(), cancellationToken);
    Use(buffer.AsSpan(0, written));
}
finally
{
    ArrayUtility.ZeroMemory(buffer.AsSpan());
}
```

An async method can't take a `Span`, so the plaintext lands in memory the caller provides: pass a
pinned array, never a pooled one, and zero it once used. Decryption itself is the same as
`Decrypt`'s; only the fetch is asynchronous. `ProtectedCacheCollection` awaits each source in turn,
so a secret-store cache in a collection doesn't block either. Every other cache - `ProtectedCache`,
`IProtectedConfigurationRoot`, any implementation written before these members existed - gets them
from the interface, where they simply call the synchronous members.

Synchronous and asynchronous lookups of the same uncached secret share one fetch. The token
cancels a lookup's wait, and the fetch itself only if that lookup started it; a lookup whose fetch
was cancelled by another caller starts a new one rather than failing.

All four derive from `RemoteSecretCache` (in `HkdfGuard.Cache`), which owns fetching, caching,
encryption, name matching and telemetry. Another secret store needs only a subclass that says which
names it can hold and reads one secret by name - and, if its client is asynchronous, how to read it
without blocking:

```csharp
public sealed class MySecretStoreCache(MyClient client, IKeyRing ring)
    : RemoteSecretCache(ring, SecretNameMatching.Exact)
{
    protected override bool IsValidName(string name) => name.All(char.IsAsciiLetterOrDigit);

    // Hand the value to the sink, or return without doing so if the secret doesn't exist.
    protected override void Fetch(string name, SecretValueSink value)
    {
        if (client.TryGet(name, out var secret))
            value.SetText(secret);
    }

    // Optional: without it, DecryptAsync calls Fetch. Hand values over between awaits.
    protected override async ValueTask FetchAsync(string name, SecretValueSink value, CancellationToken cancellationToken)
    {
        if (await client.GetAsync(name, cancellationToken) is { } secret)
            value.SetText(secret);
    }
}
```

### Pipeline protection - encrypt now, wrap later

`IPipelineDataProtector` (in Abstractions) is for the moment before a durable KEK exists - e.g. a
provisioning pipeline that must encrypt secrets in flight. It deliberately diverges from
`IDataProtector`: rather than binding one purpose at construction, every `Encrypt`/`Decrypt` takes
a `secretIdentifier` - the configuration key the value will be stored under, as its full path
(`"ConnectionStrings:Admin"`). One instance - one key - protects many secrets, each bound to its
own identifier, and a value moved to a different key fails authentication. Implementations bind
the identifier as Additional Authenticated Data through `ProtectedConfigurationPurpose`, which
every AEAD cipher supports (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV), so the interface isn't tied
to one algorithm.

`AesGcmPipelineDataProtector` implements it: a random 32-byte key generated in memory, one AES-GCM
session for its whole lifetime (no key wrapper, no refresh), and every value stamped with the key
version the key will later be registered under. Once the key is wrapped and registered at that
version, `ProtectedConfigurationRoot.Decrypt(secretIdentifier)` reveals each value (or, directly,
`ring.CreateProtector(ProtectedConfigurationPurpose.For(secretIdentifier))`).

```csharp
using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 3);
string formatted = protector.Encrypt("secret value", "ConnectionStrings:Admin");   // "enc::v3::..."

// At the end of the pipeline, hand the key to the native platform's wrap process:
ReadOnlySpan<char> base64Key = protector.GetKeyAsBase64();
```

`ProtectedConfigurationRoot` reads each value back with the same purpose the pipeline derived from
its secret identifier, so the value only decrypts under the key it was written for - an attacker who can edit the configuration file can't move an admin connection
string into a less-privileged setting.

The purpose is `HkdfGuard.EncryptedConfiguration:` plus the key with ASCII letters `a-z`
upper-cased and every other character left as it is; its UTF-8 bytes are the AAD. A key that isn't
valid UTF-16 (one holding an unpaired surrogate) is refused, as protector and cache names are,
because encoding it would substitute U+FFFD and give different keys the same AAD. Every language
port implements this same rule, so a value encrypted by one decrypts in another. Keys differing only
in ASCII case share a purpose, as they do in configuration. Keys differing in non-ASCII case, such
as `café` and `CAFÉ`, never do: reading such a value under the other spelling fails authentication
instead of revealing it. Use the same spelling to write and read any key with non-ASCII letters.
Values written under the earlier rule, which followed .NET's own case table, decrypt unchanged when
their keys are ASCII; any with non-ASCII letters must be re-encrypted, which the
fresh-key-per-deployment model does anyway.

`GetKeyAsBase64` returns a span over a buffer the protector owns. Disposing the protector zeroes
the key and that buffer, so consume the span first and never copy it into a `string`.

Hand the key to the native wrap tool on **standard input** with `--dek-stdin`, never as a
command-line argument or environment variable. Process listings, shell history, CI logs and crash
reports capture those; a pipe is visible only to the two processes on either end. Write it as bytes
from a buffer you then zero, rather than through a `string` or a `TextWriter`, whose internal
buffers can't be cleared:

```csharp
var start = new ProcessStartInfo(initializeToolPath) { RedirectStandardInput = true, UseShellExecute = false };
foreach (var arg in new[] { "wrap", "--service-name", "my.service", "--key-file-path", keyFilePath, "--dek-stdin" })
    start.ArgumentList.Add(arg);
// Add --group <a local group> to let your application's account read the key file; without it,
// only the file's owner can.

using var tool = Process.Start(start)!;
var base64Key = protector.GetKeyAsBase64();
Span<byte> ascii = stackalloc byte[base64Key.Length];
try
{
    Encoding.ASCII.GetBytes(base64Key, ascii);
    tool.StandardInput.BaseStream.Write(ascii);
    tool.StandardInput.BaseStream.Flush();
}
finally
{
    CryptographicOperations.ZeroMemory(ascii);
}
tool.StandardInput.Close();
tool.WaitForExit();
protector.Dispose(); // zeroes the key and its base64 form
```

Every platform's tool also accepts `--dek-file <path>`. Prefer stdin: a file leaves the key on disk until
it is securely deleted. On macOS, pass `--fingerprint <hex>` as well, so the tool refuses to write a
key file under any KEK other than the one recorded at provisioning.

## Diagnostics

All telemetry lives in `HkdfGuard.Diagnostics`. `HkdfGuardTelemetry` exposes one
`ComponentTelemetry` per component (`Root`, `Cache`, `DataProtection`, `EncryptedConfiguration`,
`CryptoProviderAesGcm256`, `KeyWrapping`), each with its own `ActivitySource`/`Meter` and an
`EnableSensitiveLogging` flag - `Root`/`Cache`/`DataProtection`/`EncryptedConfiguration` share one
flag; `CryptoProviderAesGcm256` and `KeyWrapping` each keep their own, independent flag. When
enabled, operations emit a fixed-name `hkdfguard.sensitive_operation` debug event. Raw key,
plaintext, and ciphertext bytes are never logged, regardless of this setting, but what the event
does carry is not nothing - decide before turning it on in production whether your tracing backend
may hold it:

- **Identifiers**: cache entry names, configuration keys, and protector purposes
  (`hkdfguard.name`). These often say what a secret is ("ConnectionStrings:Admin"). With a logger,
  `ProtectedCache` also writes each name to a debug log entry.
- **Lengths**: plaintext, ciphertext, AAD, and formatted-value lengths. A plaintext length tells
  an observer how long a secret is - enough to distinguish a 16-character password from a
  64-character API key.
- **Key versions**: which version encrypted a value, and whether an added version became current.

Activities come from `HkdfGuard.Abstractions` (`ProtectedCacheBase`, on `Root`), `HkdfGuard.Cache`
(`Cache`), `HkdfGuard.DataEncryptionKey` (`DataProtection`), `HkdfGuard.CryptoProvider.AesGcm256`
(`CryptoProviderAesGcm256`, and `DataProtection` for `AesGcmPipelineDataProtector`) and
`HkdfGuard.EncryptedConfiguration` (`EncryptedConfiguration`). Nothing emits on `KeyWrapping` yet:
the key wrappers (`NativeHkdfKeyWrapperV1`, `AwsKmsKeyWrapper`, `AzureKeyVaultKeyWrapper`) and
`HkdfGuard.SecureFile` record no activities of their own, so wrapping, unwrapping and key-file
reads show up in a trace only inside the key ring or provider activity that called them, if any.

Independently of this flag, failures are always recorded on the current activity
(`RecordException`), and an exception message can name the entry involved - for example a
duplicate `ProtectedCache.Add` names the existing entry. None includes key or plaintext bytes.

Span, event, attribute, and metric names all follow OpenTelemetry semantic-convention style -
lowercase, dot-separated (e.g. `hkdfguard.cache.add`, attribute `hkdfguard.plaintext_length`) - see
`ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames`. This naming is the part of the design
meant to translate identically into each Java/Node/Python/Go port's own OpenTelemetry SDK.

`ProtectedCache` is the pattern class for this project's newer metrics/logging extension points:
it accepts an optional, nullable `ILogger<ProtectedCache>` (via `HkdfGuardLoggerExtensions`'
source-generated `[LoggerMessage]` methods) alongside its existing `Activity` telemetry, and
increments `CacheMetrics.Operations` (a `Counter<long>` on `HkdfGuardTelemetry.Cache.Meter`) on
every Add/AddOrUpdate. Rolling the same optional-logger/metrics pattern out to every other
component is deliberate future work, not yet done everywhere.

## Testing

Each library has a corresponding xUnit test project, measured on its own (each library by its own
test project only) via `coverlet`:

```bash
dotnet test test/HkdfGuard.DataEncryptionKey.Test --collect:"XPlat Code Coverage"
```

Every library is at 100% line and branch coverage, with two documented exceptions:

- **Native bindings** (`LinuxHkdfGuardKmsLibrary`/`MacOsHkdfGuardKmsLibrary`/
  `WindowsHkdfGuardKmsLibrary`, the `WinTrust` signature check, and the system calls in
  `MacOsNative` and `LinuxNative`) are marked `[ExcludeFromCodeCoverage]`. They are thin P/Invoke
  bindings that can only run on their own operating system. The loaders' decisions are covered
  everywhere: the Windows checks run against the real installed DLL on Windows, the macOS and
  Linux checks run against simulated filesystems on every platform, and the Linux checks also run
  against the real filesystem and the installed package on Linux. `NativeProcessHardening.Apply()`
  hardens the whole test host, so its tests (Windows and Linux) run only with
  `HKDFGUARD_TEST_PROCESS_HARDENING=1`.
- **`AesGcmCryptoProvider`'s refresh loop and `KeyRing`'s ephemeral rotation loop** each have one
  unreachable branch: the loop's exit when its `PeriodicTimer` reports it has been disposed. Each
  timer is local to its loop and disposed only after it, so this never happens; the check stays as
  a guard against a future busy loop.

`NativeKeyWrappingIntegrationTests` make real calls against a provisioned service. They are
reported as skipped, never passed, unless `HKDFGUARD_TEST_SERVICE` names one. Set
`HKDFGUARD_TEST_SERVICE_OTHER` to a second provisioned service to test cross-service isolation
against a different KEK:

```bash
hkdfguard provision --service-name hkdfguard.integrationtest   # elevated on Windows
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest dotnet test test/HkdfGuard.KeyWrapping.V1.Test
```

On a Linux host with a TPM, the package installs no policy or TPM derivation secret, so nothing
can be provisioned until root adds them. `scripts/provision-linux-test-key.sh` does that for a test
host: run it once with `sudo` from the account that runs the tests (which must be in the `tss`
group). It creates the derivation secret if there is none, writes a policy that requires the TPM
and pins the test service's TPM Name, and confirms it as that account. It never replaces a
policy it didn't write or an existing secret; `--remove` removes its policy again. With it in place,
`LinuxNativeIntegrationTests` also run: they check the exact Linux status codes, the native
library's own service-name and length checks, that a failed unwrap zeroes the caller's buffer,
that tampering anywhere in a payload is refused, and that a key file written by
`hkdfguard wrap` unwraps through `NativeHkdfKeyWrapperV1`.

```bash
sudo scripts/provision-linux-test-key.sh
HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
dotnet test test/HkdfGuard.KeyWrapping.V1.Test
```

`AwsKmsIntegrationTests` make real calls against a symmetric KMS key. They are reported as skipped,
never passed, unless `HKDFGUARD_TEST_AWS_KMS_KEY_ID` names one. Credentials and region come from the
SDK's usual chain. The tests never create, alter or delete a key:

```bash
HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:111122223333:key/... AWS_REGION=us-east-1 \
dotnet test test/HkdfGuard.KeyWrapping.AwsKms.Test
```

[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md) sets up a test
key and a low-privilege IAM user, and keeps the key ARN in a git-ignored runsettings file instead
of the environment.

`AzureKeyVaultIntegrationTests` make real calls against an RSA wrapping key and an EC P-256
signing key. They are reported as skipped, never passed, unless `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID`
and `HKDFGUARD_TEST_AZURE_SIGN_KEY_ID` both name one, which the git-ignored `azure.runsettings`
does. Credentials come from `DefaultAzureCredential` (for example `az login`):

```powershell
dotnet test test/HkdfGuard.KeyWrapping.AzureKeyVault.Test --settings azure.runsettings
```

[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md)
sets up a test vault, both keys and your role on them.

`GoogleKmsIntegrationTests` make real calls against a symmetric Cloud KMS key. They are reported
as skipped, never passed, unless `HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME` names one, which the
git-ignored `google.runsettings` does. Credentials come from Application Default Credentials (for
example `gcloud auth application-default login`):

```powershell
dotnet test test/HkdfGuard.KeyWrapping.GoogleKms.Test --settings google.runsettings
```

[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md) sets
up a test key and your role on it.

### Native integration test coverage

The same platform native integration cases exist in every HkdfGuard port (.NET, Java, Python, Go,
Node). In `HkdfGuard.KeyWrapping.V1.Test` each platform's suite is reported as skipped - never
passed - where its platform, library or service isn't there:

- **Windows** - `WindowsNativeLibraryLoaderTests` (installed-library cases), `NativeKeyFileTests`,
  `NativeKeyWrappingIntegrationTests`, `NativeEndToEndTests`, `NativeProcessHardeningTests`. The
  installed-library cases run wherever `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` is installed;
  the round trips also need a provisioned KEK - `HKDFGUARD_TEST_SERVICE`, or
  `com.hkdfguard.integration.test.221` (`scripts/provision-windows-test-key.ps1`), which the
  installed library's `hkdfguard_kek_exists` confirms. The script also retires the legacy
  per-platform test KEK `com.hkdfguard.native.windows.test`, after asking (`-KeepLegacyKey` keeps
  it), and `-Remove` retires the test KEKs instead - each only after `hkdfguard status` confirms its
  fingerprint (`-WhatIf` shows what would be deleted).
- **Linux** - `LinuxNativeLibraryLoaderSystemTests` run against the real filesystem and dynamic
  linker on any Linux host, with their installed-library cases needing the `libhkdfguard1`
  package; `LinuxNativeIntegrationTests` also need `HKDFGUARD_TEST_SERVICE`, and some
  `HKDFGUARD_TEST_SERVICE_OTHER`, the policy's `tpm.require_pinned_names`, or `/usr/bin/hkdfguard`
  (see `scripts/provision-linux-test-key.sh` above). The Linux library refuses a key file below
  any group- or other-writable directory, sticky or not, so the tests that write one use a private
  (0700) folder under `$XDG_RUNTIME_DIR` or `~/.cache/hkdfguard-tests` - never `/tmp` - and are
  reported as skipped, with the reason, where neither is trusted.
- **macOS** - `MacOsNativeIntegrationTests` run on macOS against the real filesystem and Security
  framework, with their installed-library cases needing `libhkdfguard.dylib` at
  `/Library/Application Support/HkdfGuard/v1` (or `~/.hkdfguard/v1`) and `hkdfguard`
  beside it. The shared round trips run against `HKDFGUARD_TEST_SERVICE`, or
  `com.hkdfguard.integration.test.221` when `hkdfguard status` reports it present.
  The first call under that service from a freshly built test host can raise a keychain dialog
  ("Always Allow"); if nobody answers it within 60 seconds the tests fail and say so, rather than
  hang.

`NativeProcessHardeningTests` harden the test host itself, so they also need
`HKDFGUARD_TEST_PROCESS_HARDENING=1`, and are best run one at a time.

Native release artifacts are never committed: `.gitignore` excludes every `runtimes/` folder.

## Signing and releases

### What is signed

Every assembly built from this repository (`HkdfGuard.*.dll`, for every target framework) is
Authenticode-signed through Azure Artifact Signing before it is packed. That is the same account
and certificate profile (`RunSecureSigning` / `runsecure-release`) that signs the native
`HkdfGuard.dll`, so the publisher is `CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US`.
Artifact Signing certificates are valid for about three days, so every signature is RFC 3161
timestamped. That keeps it valid after the certificate expires.

**The NuGet packages themselves are not author-signed.** The assemblies inside them are signed;
the `.nupkg` and `.snupkg` files are not. nuget.org can't yet accept Artifact Signing's
short-lived certificates without registering each new certificate by hand
([NuGet/NuGetGallery#10027](https://github.com/NuGet/NuGetGallery/issues/10027)). nuget.org adds
its own repository signature to every package it accepts.

Third-party and framework assemblies are never signed by this repository. Signing is separate
from strong naming, which these assemblies don't use.

### Cutting a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The tag must be `vMAJOR.MINOR.PATCH`, optionally with a pre-release suffix (`v1.2.0-rc.1`). The
version without the `v` is stamped into every assembly and package. The **Release** workflow
(`.github/workflows/release.yml`) then:

1. **build** (the shared `build.yml`, the same one CI runs): restores the locked dependency
   graph, builds Release, runs the tests, and uploads the unsigned output. It holds no signing
   access.
2. **sign** (Windows x64, in the `release` environment): signs each project's assembly, packs with
   `--no-build` so the packages carry the signed assemblies, opens every package to verify each
   assembly in it is validly signed and timestamped, and attests build provenance of the packages
   and assemblies. Any failure fails the release; there is no unsigned fallback.
3. **publish**: creates a GitHub Release with every `.nupkg`, `.snupkg` and `.sha256`. Versions
   `0.x`, and any with a pre-release suffix, are published as GitHub pre-releases.

Nothing is pushed to a NuGet feed yet.

The **CI** workflow (`ci.yml`) runs on every push to `main` and every pull request. It builds,
tests and packs exactly as a release does, but unsigned, with no secrets, no `release` environment
and no Azure sign-in.

### One-time setup

These are Azure and GitHub settings, not code:

1. **Federated credential.** On the Entra app registration that `hkdfguard-native-windows` signs as
   (or a new app with the same role), add a federated credential for this repository's `release`
   environment, with subject `repo:runsecure/hkdfguard-dotnet:environment:release`. A credential for
   a branch or tag doesn't match a job that runs in an environment.
2. **Role.** The app holds **Artifact Signing Certificate Profile Signer** on the `RunSecureSigning`
   account or the `runsecure-release` profile. This is already true if you reuse the native repo's app.
3. **Repository secrets:** `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID`. There is no
   client secret; sign-in is OIDC only.
4. **Environment.** Create a `release` environment (Settings > Environments) restricted to tags
   matching `v*`, so only a release can reach the signing account.

The signing account, profile and endpoint are in `build/signing/metadata.json`, which holds no
secrets.

### Signing on a developer machine

```powershell
scripts\build-signed.bat -Version 0.1.0
```

This checks the signing setup first, then cleans, builds, tests, signs, packs into
`artifacts\packages`, and verifies the assemblies inside every package. It needs:

- Windows x64, with the Windows SDK signing tools 10.0.22621 or newer (`signtool.exe`);
- the Artifact Signing client tools: `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`;
- the Azure CLI, signed in (`az login`) as an account holding the Signer role above.

The signing helpers are `scripts/ArtifactSigning.ps1` (ported from `hkdfguard-native-windows`) and
`scripts/HkdfGuardPackaging.ps1`.

### Verifying a package

A `.nupkg` is a zip file. Extract it and check the assembly:

```powershell
Expand-Archive HkdfGuard.DataEncryptionKey.1.0.0.nupkg -DestinationPath pkg   # rename to .zip first on Windows PowerShell 5.1
Get-AuthenticodeSignature pkg\lib\net10.0\HkdfGuard.DataEncryptionKey.dll |
    Format-List Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`, the signer `CN=Torin Blair, ...`, and `TimeStamperCertificate` set.

Check the package came from this repository's release workflow:

```bash
gh attestation verify HkdfGuard.DataEncryptionKey.1.0.0.nupkg --repo runsecure/hkdfguard-dotnet
```

Attestations need a public repository, or GitHub Enterprise Cloud for a private one.

`dotnet nuget verify --all <package>.nupkg` reports a package downloaded from nuget.org as
repository-signed by nuget.org. A package taken from a GitHub Release is unsigned at the NuGet
level, as described above.

## License

HkdfGuard is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0), and every NuGet
package declares `MPL-2.0` as its license. The MPL applies file by file: you can combine these
libraries with code under other licenses, including proprietary code, but changes you make to
HkdfGuard's own source files must be made available under the MPL 2.0 when you distribute them.
