# HkdfGuard

A C# library for protecting data-at-rest encryption keys using native, platform-backed key
management (TPM2 on Linux, Secure Enclave on macOS, the Platform Crypto Provider/TPM on Windows -
see `HkdfGuard.KeyWrapping.V1`) combined with AES-GCM for the actual data encryption. Application
code works against a `KeyRing` to encrypt/decrypt strings and binary data, with key-version
tracking and purpose-scoped Additional Authenticated Data (AAD).

## Key concepts

- **The KEK never enters this process, and a revealed DEK is held only as long as configured.**
  Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native KMS library
  for the current OS (`NativeHkdfKeyWrapperV1`) - the KEK never leaves that native library. This
  library sees the wrapped payload and the revealed DEK, which it caches in memory for at most the
  configured expiry (1-300 seconds) and zeroes when replaced or disposed; it never writes a
  plaintext DEK to disk.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself. `KeyRingBuilder` carries this,
  along with a cache-expiry/rotation policy, fluently.
- **One `IKeyWrapper` per KEK, not per wrapped payload.** `IKeyWrapper.UnwrapAsync` takes the
  wrapped payload as an explicit argument, so a single wrapper instance (bound only to a KEK - e.g. a
  `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped DEKs
  sharing that KEK, one per registered key file. Its methods (`WrapAsync`/`UnwrapAsync`/
  `GenerateAndWrapAsync`) are asynchronous so network-backed KEKs can be awaited; the native
  wrapper completes synchronously.
- **Cached, expiring, proactively-refreshed cipher sessions via `ICryptoProvider`.** A revealed
  DEK is bound into an internal cipher session once, not re-derived on every Encrypt/Decrypt - the
  configured expiry (1-300 seconds) marks when it should be refreshed instead of reused.
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
  restart. So revoking the KEK stops a running process within about `3 × CachedKeyExpiry`.
  `WithMaxRefreshFailures(n)` (or `HkdfGuardOptions.MaxRefreshFailures`) changes `n`; pick it so
  that `n × CachedKeyExpiry` is longer than any KEK outage you'd rather ride out.
  `WithFailOpenOnRefreshFailure()` (or `HkdfGuardOptions.FailOpenOnRefreshFailure`) opts out: the
  last good session then stays in use indefinitely, and revoking the KEK never stops the process.
  Either way, give the factory a logger - `new AesGcmCryptoProviderFactory(logger)` - and every
  failed refresh is logged as an error, a suspension as critical, and a resumption as
  information; under fail-open that error is the only sign the KEK is gone. (Providers created
  directly through `ICryptoProviderFactory` or `AesGcmCryptoProvider.CreateAsync` still treat a
  null `maxRefreshFailures` as fail-open; the secure default lives in `KeyRingBuilder`.) The concrete
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
- **Built-in telemetry.** Every library emits `System.Diagnostics.ActivitySource` activities
  (OpenTelemetry-compatible) with exceptions recorded on failure, and an opt-in sensitive-logging
  mode that emits operation metadata (never raw key/plaintext/ciphertext bytes).

## Key rotation

The library has no rotation schedule of its own, by design. Each kind of key is rotated by an
event outside the running process:

| Key | Rotated when | How |
|---|---|---|
| Data encryption keys in key files | Every release | The release pipeline generates a fresh DEK, re-encrypts that release's configuration under it, wraps it into a new key file, and deploys the file. Nothing is carried over from the previous release. |
| Ephemeral keys (`WithEphemeralKey`) | Every 24 hours by default, and on every application restart | Generated in memory and never written anywhere. On a schedule the ring generates a fresh one and adds it as the next version, so every later `Encrypt` uses it. A restart discards them all and builds a new ring. |

Scheduled ephemeral rotation only ever adds keys. Earlier ephemeral keys stay registered, so
values encrypted under them still decrypt until the process restarts. Configure the schedule on
the builder, or in configuration through `HkdfGuardOptions`:

```csharp
builder.WithEphemeralKeyRotation(TimeSpan.FromHours(6)); // 1 minute to ~49 days; default 24 hours
builder.WithoutEphemeralKeyRotation();                   // keep the startup key until restart
builder.WithLogger(logger);                              // ILogger<KeyRing>: logs each rotation and failure
```

```jsonc
{ "EphemeralKeyRotationHours": 6 }          // 1-1193
{ "DisableEphemeralKeyRotation": true }
```

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
- **A background refresh is not a rotation.** Every `CachedKeyExpiry` seconds a provider re-reveals
  the same key, to confirm the KEK is still reachable. It never changes which key encrypts; only a
  release, a restart, or a scheduled ephemeral rotation does that.
- **Old ephemeral keys accumulate until restart.** Each one keeps its own background refresh
  running. At the default schedule that is one more key per day of uptime, so a process that runs
  for months carries months of keys. Restarting periodically resets this.

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
| `HkdfGuard.Abstractions` | Interfaces and pure data types only (`IKeyRing`, `IKeyWrapper`, `ICryptoProvider`, `ICryptoProviderFactory`, `IDataEncryptionKey`, `IDataProtector`, `IProtectedCache`/`IProtectedReadOnlyCache`, `IEncryptedFormatProvider`, `KeyTrackingValue`, `ArrayUtility`, `ProtectedCacheBase`). Depends only on `HkdfGuard.Diagnostics`. |
| `HkdfGuard.CryptoProvider.AesGcm256` | `AesGcmCryptoSession` (internal, key-bound at construction) wrapped directly by the public `AesGcmCryptoProvider` (an `ICryptoProvider` that reveals/refreshes it from an `IKeyWrapper` + wrapped bytes, and only ever holds one active session at a time; also exposes `GetEncryptedAllocationLength`/`GetDecryptedAllocationLength` for sizing buffers), minted via `AesGcmCryptoProviderFactory` (an `ICryptoProviderFactory`); plus `AesGcmPipelineDataProtector` (an `IPipelineDataProtector` over one in-memory key, for protecting values in a pipeline before a durable KEK exists - see below). Depends on `HkdfGuard.Abstractions`/`HkdfGuard.Diagnostics`; its `HkdfGuardTelemetry.CryptoProviderAesGcm256` component keeps its own independent `EnableSensitiveLogging` flag rather than sharing `Root`'s. |
| `HkdfGuard.KeyWrapping.V1` | `NativeHkdfKeyWrapperV1` (an `IKeyWrapper`, whose async methods complete synchronously) and `NativeHost`, which resolve and bind the current OS's native KMS library (Linux/.so, macOS/.dylib, Windows/.dll - see `Interop/`) to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `HkdfGuard.DataEncryptionKey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `IDataProtector`/`DataProtector`, `DataEncryptionKey` (the `IDataEncryptionKey` over an `ICryptoProvider` - output sizing and telemetry; disposing it disposes its provider), and the default `enc::v{version}::{base64}` wire format. Depends on `HkdfGuard.Abstractions`/`HkdfGuard.Diagnostics`. |
| `HkdfGuard.Cache` | `ProtectedCache` (an `IProtectedCache` backed by an `IKeyRing` - encrypts under the ring's current key on Add/AddOrUpdate and records its version, reveals under that version on Decrypt, so it follows key rotation; nothing held as plaintext beyond a single call; each value is bound to its name as AAD, so a ciphertext under any other name fails authentication, and names match ignoring ASCII case only) and `ProtectedCacheCollection` (aggregates multiple `IProtectedReadOnlyCache` sources behind one read-only surface, checked in registration order). |
| `HkdfGuard.EncryptedConfiguration` | `ProtectedConfigurationRoot` (an `IProtectedConfigurationRoot`) - wraps an `IConfigurationRoot`, revealing values formatted as protected secrets via a `KeyRing`; configuration itself only ever holds ciphertext, and `Decrypt` reads fresh from the underlying root every time so `Reload` takes effect immediately. Each value is bound to its own configuration key (`ProtectedConfigurationPurpose`), so a value copied to another key fails to decrypt. |
| `HkdfGuard.DependencyInjection` | `AddKeyRingAsync` - builds a `KeyRing` asynchronously at registration and registers it as a singleton in an `IServiceCollection`. |
| `HkdfGuard.Options` | `HkdfGuardOptions`/`HkdfGuardOptionsValidator`/`HkdfGuardOptionsExtensions.ApplyTo` - a plain-data mirror of `KeyRingBuilder`'s configuration surface (`ServiceName`, `CachedKeyExpiry`, `MaxRefreshFailures`/`FailOpenOnRefreshFailure`, key files, ephemeral keys), for binding a `KeyRing`'s identity/policy/key files from configuration. |
| `HkdfGuard.Diagnostics.Test`, `HkdfGuard.Abstractions.Test`, `HkdfGuard.CryptoProvider.AesGcm256.Test`, `HkdfGuard.KeyWrapping.V1.Test`, `HkdfGuard.DataEncryptionKey.Test`, `HkdfGuard.Cache.Test`, `HkdfGuard.EncryptedConfiguration.Test`, `HkdfGuard.DependencyInjection.Test`, `HkdfGuard.Options.Test` | xUnit test suites, maintained at full line/branch coverage for their respective projects. |

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
`hkdfguard-v1-initialize provision --service-name <name>` (elevated on Windows), or every call fails.
A service name is 1-128 ASCII letters, digits or dots, never starts with a dot and never contains
`..`, so `my.service` rather than `my-service`. `ServiceNames` holds the rule. `NativeHkdfKeyWrapperV1`,
`KeyRingBuilder.WithServiceName` and the options validator all enforce it, so a bad name fails
with a message saying which rule it broke, before any native call.

Where each platform's library comes from:

| Platform | Library | How it is found |
|---|---|---|
| Windows | `HkdfGuardV1.dll` | Installed to `%ProgramFiles%\HkdfGuard\v1` and loaded only from there. Not shipped in the package. |
| macOS | `libhkdfguard_v1.dylib` | Installed system-wide to `/Library/Application Support/HkdfGuard/v1`, or per user to `~/.hkdfguard/v1`, and loaded only from there. Not shipped in the package. |
| Linux | `HkdfGuardKeyProtectionLinux` | The runtime's default search. |

The NuGet package contains no native library. Each one is distributed and installed separately,
together with its `hkdfguard-v1-initialize` provisioning tool.

The library sees every DEK, so on Windows and macOS it is never located by a search path.

On **Windows**, before mapping it, `WindowsNativeLibraryLoader` requires all of the following:
- No folder on its path is a symlink or junction.
- The file and every parent folder below the drive root are owned and writable only by SYSTEM,
  Administrators or TrustedInstaller.
- The file has a valid, trusted Authenticode signature from the expected publisher.

Its dependencies are then loaded from System32 only. Any failed check throws, with no fallback, so
a DLL planted on `PATH` or beside the application is never loaded.

On **macOS**, `MacOsNativeLibraryLoader` uses the system install whenever it exists, and the
per-user install only when there is no system install. Anything running as the user can write to
the user's home, so a per-user file must never be able to override a root-owned system one. If the
system install exists but fails a check, loading fails instead of falling back. Before loading,
it requires all of the following:
- No component of the path, up to `/`, is a symbolic link.
- Every component of a system install is owned by root; of a user install, by root or the current
  user.
- No component is writable by anyone but its owner. The one exception is root-owned directories
  writable by the `wheel` or `admin` group, as `/Library/Application Support` is.
- The file's code signature is valid, carries the identifier `libhkdfguard_v1`, and was made with
  a Developer ID Application certificate issued through Apple's CA to the HkdfGuard team
  (`MFW3T8R8J3`). A development-signed build, or any other binary the team signs, is refused.

The library's own dependencies are absolute system paths, so `DYLD_LIBRARY_PATH` can't redirect
them.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation
policy, a shared `IKeyWrapper` and an `ICryptoProviderFactory`, and any number of wrapped-DEK
files - one per version - then reads each file, mints its own `ICryptoProvider` (via
`ICryptoProviderFactory.CreateAsync`), and wires it into a `DataEncryptionKey`.
`WithEphemeralKey` registers a version whose key is instead generated fresh at build time (via
`ICryptoProviderFactory.CreateEphemeralAsync`) and never written to disk - it shares the same
`IKeyWrapper`/`ICryptoProviderFactory`, so no extra configuration is needed for it. Range checks
happen in the setters (`WithServiceName`, `WithCachedKeyExpiry`, `WithMaxRefreshFailures`); `BuildAsync` checks that a key
wrapper, a crypto provider factory, a cached key expiry (there's no default), and at least one key
were configured. Each key file must hold 1 to `WrappedKeyLimits.MaxBytes` (512) bytes; `BuildAsync`
never reads more than one byte past that, so pointing it at the wrong file can't make startup
allocate an unbounded buffer. The limit leaves room for larger keys and extra fingerprinting
beyond today's 156-byte macOS payload; raising that one constant also resizes the buffer an
ephemeral key is generated into. If anything fails or is cancelled partway through, every provider
it already created is disposed.

Building is asynchronous only: `BuildAsync` reads the key files and reveals every key through the
key wrapper without blocking a thread, which matters once the key wrapper is network-backed (a
cloud KMS). There is no synchronous `Build()` - await it at startup.

```csharp
var ring = await new KeyRingBuilder()
    .WithServiceName("my.service")
    .WithCachedKeyExpiry(60)   // seconds, 1-300 - required before building
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
    .WithCachedKeyExpiry(60)
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
upper-cased and every other character left as it is; its UTF-8 bytes are the AAD. Every language
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
// Windows also requires --group <the local group allowed to read the key file>.

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

The macOS tool also accepts `--dek-file <path>`. Prefer stdin: a file leaves the key on disk until
it is securely deleted. On macOS, pass `--fingerprint <hex>` as well, so the tool refuses to write a
key file under any KEK other than the one recorded at provisioning.

## Diagnostics

All telemetry lives in `HkdfGuard.Diagnostics`. `HkdfGuardTelemetry` exposes one
`ComponentTelemetry` per component (`Root`, `Cache`, `DataProtection`, `EncryptedConfiguration`,
`CryptoProviderAesGcm256`, `KeyWrapping`), each with its own `ActivitySource`/`Meter` and an
`EnableSensitiveLogging` flag - `Root`/`Cache`/`DataProtection`/`EncryptedConfiguration` share one
flag; `CryptoProviderAesGcm256` and `KeyWrapping` each keep their own, independent flag. When
enabled, operations emit a fixed-name `hkdfguard.sensitive_operation` debug event carrying only
non-sensitive metadata (lengths, versions, identifiers) as attributes - raw key, plaintext, and
ciphertext bytes are never logged, regardless of this setting.

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
  `WindowsHkdfGuardKmsLibrary`, the `WinTrust` signature check, and the macOS system calls in
  `MacOsNative`) are marked `[ExcludeFromCodeCoverage]`. They are thin P/Invoke bindings that can
  only run on their own operating system. The loaders' decisions are covered everywhere: the
  Windows checks run against the real installed DLL on Windows, and the macOS checks run against
  simulated filesystems on every platform.
- **`AesGcmCryptoProvider`'s refresh loop and `KeyRing`'s ephemeral rotation loop** each have one
  unreachable branch: the loop's exit when its `PeriodicTimer` reports it has been disposed. Each
  timer is local to its loop and disposed only after it, so this never happens; the check stays as
  a guard against a future busy loop.

`NativeKeyWrappingIntegrationTests` make real calls against a provisioned service. They are
reported as skipped, never passed, unless `HKDFGUARD_TEST_SERVICE` names one. Set
`HKDFGUARD_TEST_SERVICE_OTHER` to a second provisioned service to test cross-service isolation
against a different KEK:

```bash
hkdfguard-v1-initialize provision --service-name hkdfguard.integrationtest   # elevated on Windows
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest dotnet test test/HkdfGuard.KeyWrapping.V1.Test
```

Native release artifacts are never committed: `.gitignore` excludes every `runtimes/` folder.
Where one is present locally, `.gitattributes` keeps it byte-exact and `NativeRuntimesTests` fails
if any file stops matching its `SHA256SUMS`.

## License

HkdfGuard is licensed under the [Mozilla Public License 2.0](LICENSE) (MPL-2.0), and every NuGet
package declares `MPL-2.0` as its license. The MPL applies file by file: you can combine these
libraries with code under other licenses, including proprietary code, but changes you make to
HkdfGuard's own source files must be made available under the MPL 2.0 when you distribute them.
