# Call Vault's API with the HashiCorp Vault client

This page uses `VaultClient`, from the package `HkdfGuard.Integration.HashiCorpVault`, to call
HashiCorp Vault's HTTP API from .NET: logging in, managing auth methods, secrets engines, policies,
PKI, and anything else Vault exposes. It's a port of HashiCorp's
[vault-client-go](https://github.com/hashicorp/vault-client-go), generated from the same OpenAPI
spec, and it holds Vault tokens the way the rest of HkdfGuard does: only in protected form.

To read secrets into memory your application uses, prefer `HashiCorpVaultSecretCache` (package
`HkdfGuard.Cache.HashiCorpVault`). It reads each secret straight into pinned memory and keeps it
encrypted. `VaultClient` returns response data as ordinary .NET strings and JSON values, like any
other API client.

## 1. Create a client

A client needs a token protector: a protector on your application's key ring, created for
`VaultClient.TokenPurpose`. Every token the client holds is encrypted with it.

```csharp
using HkdfGuard.Integration.HashiCorpVault;
using HkdfGuard.Integration.HashiCorpVault.Schema;

// keyRing is your application's KeyRing; see Getting started.
var tokenProtector = keyRing.CreateProtector(VaultClient.TokenPurpose);

using var vault = new VaultClient(tokenProtector, new VaultClientOptions
{
    Address = new Uri("https://vault.example.com:8200"),
});
```

Or take every setting from the environment variables vault-client-go and the `vault` CLI read
(`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT` and the rest):

```csharp
using var vault = new VaultClient(tokenProtector, VaultClientOptions.FromEnvironment(tokenProtector));
```

`FromEnvironment` protects `VAULT_TOKEN` with the protector you pass. Without a protector it ignores
`VAULT_TOKEN`.

> **Security:** The address must be `https`. Plain `http` is allowed only on a loopback address (a
> local Vault Agent or dev server), or when you set `AllowUnencryptedHttp`, because every request
> carries a token.

## 2. Authenticate

Log in with any auth method. The `Auth` methods are generated, one per endpoint. The token in the
response is protected as the response is read, so it never becomes a string. Hand it straight to the
client:

```csharp
var login = await vault.Auth.AppRoleLoginAsync(new AppRoleLoginRequest
{
    RoleId = roleId,
    SecretId = secretId,
});
vault.SetToken(login!.Auth!.ClientToken!);
```

For a token you already hold, `vault.SetToken(token)` protects it and keeps only the protected form.
These are the same token types `HashiCorpVaultSecretCache` takes. A protected token only works for the
protector it was protected with, though, and the cache's purpose (`HashiCorpVaultSecretCache.TokenPurpose`)
isn't the client's, so protect a token separately for each.
Clear your own copy afterwards. To log in, renew and replace tokens on your own schedule, implement
`IVaultTokenProvider`; the client asks it for a protected token on every request.

## 3. Call Vault

The generated methods are grouped as vault-client-go groups them: `vault.Auth`, `vault.Identity`,
`vault.Secrets` and `vault.System`. Each method is named after the endpoint's operation ID
(`kv-v2-read` is `KvV2ReadAsync`), takes the path's parameters and a typed request body, and returns
a typed response from the `Schema` namespace.

```csharp
// The engine's default mount is "kv-v2"; a dev server mounts KV version 2 at "secret".
var kv = new VaultRequestOptions { MountPath = "secret" };

await vault.Secrets.KvV2WriteAsync("myapp/config", new KvV2WriteRequest
{
    Data = new Dictionary<string, object?> { ["feature"] = "on" },
}, kv);

var config = await vault.Secrets.KvV2ReadAsync("myapp/config", kv);
var feature = config!.Data!.Data!["feature"].GetString();

var mounts = await vault.System.MountsListSecretsEnginesAsync();
```

The generic methods reach any path, typed or not:

```csharp
var raw = await vault.ReadAsync("sys/mounts");
await vault.WriteAsync("secret/data/myapp/flags", new Dictionary<string, object?>
{
    ["data"] = new Dictionary<string, object?> { ["beta"] = true },
});
var keys = await vault.ListAsync("secret/metadata/myapp");
await vault.DeleteAsync("secret/metadata/myapp/flags");
```

`VaultRequestOptions` sets things for one request: another token, a namespace, extra headers or
query parameters, MFA credentials, response wrapping, or a forwarding mode. The client's own
`Set...` methods set them for every later request, and a request's settings win over the client's.

### Wrap and unwrap a response

```csharp
var wrapped = await vault.Secrets.KvV2ReadAsync("myapp/config", kv with { ResponseWrappingTtl = TimeSpan.FromMinutes(5) });
var unwrapped = await vault.UnwrapAsync<KvV2ReadResponse>(wrapped!.WrapInfo!.Token!);
```

The wrapping token is protected by this client's protector. A process with a different key ring
can't use it as it is.

### Handle errors

Vault's refusals throw `VaultResponseException`, with Vault's status and error messages. A redirect
the client won't follow throws `VaultRedirectException`. Both derive from `HttpRequestException`.
A request that outlives `RequestTimeout` (60 seconds by default) throws `TimeoutException`.

```csharp
try
{
    await vault.Secrets.KvV2ReadAsync("myapp/missing", kv);
}
catch (VaultResponseException e) when (VaultClient.IsErrorStatus(e, HttpStatusCode.NotFound))
{
    // No such secret.
}
```

## How it differs from vault-client-go

| | vault-client-go | `VaultClient` |
|---|---|---|
| Tokens | Plain strings (`SetToken(string)`) | Protected by the token protector; decrypted only into the request's header, zeroed once it's sent |
| Login and wrapping tokens in responses | Strings | Protected as they're read (`StaticVaultToken`) |
| Address | Any scheme | `https`, or `http` on loopback, or `unix://`; any other `http` needs `AllowUnencryptedHttp` |
| Redirects | Follows one, never `https` to `http` | Refused (`VaultRedirectException`) unless `FollowRedirects` is set; then as vault-client-go |
| Address with a path | Path dropped | Kept as a prefix, for Vault behind a reverse proxy |
| Free-form values | `map[string]interface{}` | `Dictionary<string, object?>` sent, `Dictionary<string, JsonElement>` returned |
| Optional fields | Zero values left out (`omitempty`) | Nullable; null left out, so `false` and `0` can be sent |
| Response fields Vault types differently from its spec | Decoding fails | A number where the spec says string is read as its text |
| Rate limiting | `rate.Limiter` | `VaultRateLimiter`, the same token bucket |
| Retries, MFA, namespaces, replication, callbacks, TLS, unix sockets | Yes | Yes, as vault-client-go |
| Every request | | Sends `X-Vault-Request: true`, as the `vault` CLI does |

## Regenerate from a newer spec

The `Generated/` folder is produced by `tools/HkdfGuard.Integration.HashiCorpVault.Generator` from
`src/HkdfGuard.Integration.HashiCorpVault/openapi.json`, which is vault-client-go's spec (Vault API
1.15.0). As in vault-client-go, operations whose ID ends in `2`, `3` or `4` (alternative paths to the
same endpoint) or starts with `enterprise-stub` are left out, along with their schemas.

To update:

1. Replace `openapi.json` with the newer spec. The simplest source is vault-client-go's own
   `openapi.json`. A spec read from your own Vault must use generic mount paths
   (`{kv_v2_mount_path}` and so on), as vault-client-go's does: the generator turns those into
   `VaultRequestOptions.MountPath` and needs a default for each.
2. From the repository root, run:

   ```bash
   dotnet run --project tools/HkdfGuard.Integration.HashiCorpVault.Generator
   ```

   It rewrites only the files that changed and deletes those the spec no longer produces.
3. Build and test. `GeneratedApiTests.TheGeneratedCode_IsWhatTheSpecGenerates` fails whenever the
   checked-in code isn't what the spec generates, so a hand edit to `Generated/` doesn't survive.

If the generator meets something it doesn't handle, such as an inline object with its own
properties or a header parameter, it stops with an `InvalidDataException` naming the operation or
schema. Extend `VaultClientGenerator` rather than editing its output.

## Run the integration tests

`VaultClientIntegrationTests` write, read and delete secrets under `secret/hkdfguard-client-test/`
on a Vault dev server, wrap and unwrap a response, and create and revoke a token. They run only
when `HKDFGUARD_TEST_VAULT_TOKEN` is set and `HKDFGUARD_TEST_VAULT_ADDR` is a loopback address.
Otherwise they're reported as skipped.

```bash
docker run --rm -d --name vault-dev -p 8200:8200 hashicorp/vault server -dev -dev-root-token-id=dev-root
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=dev-root \
  dotnet test test/HkdfGuard.Integration.HashiCorpVault.Test
```

For a dev server started with `-dev-tls`, use its `https` address and set
`HKDFGUARD_TEST_VAULT_CACERT` to the CA certificate it prints. The tests trust it through
`VaultTlsOptions.ServerCertificateFile`.
