# Resolve configuration templates from protected caches

This page fills the `${name}` items in a template, such as a connection string or a configuration
file, with secrets from HkdfGuard's protected caches. It uses
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) for the
templates, and `ProtectedCacheValueProvider`, from the package
`HkdfGuard.Integration.ConfigurationResolver`, to read the values.

Any `IProtectedReadOnlyCache` can supply the values:

- a `ProtectedCache` or `FilePerSecretCache`
- an `IProtectedConfigurationRoot`, for `enc::` values in your configuration
- a remote secret store's cache: `HashiCorpVaultSecretCache`, `AwsSecretsManagerSecretCache`,
  `AzureKeyVaultSecretCache` or `GoogleSecretManagerSecretCache`

ConfigurationResolver on its own needs no HkdfGuard. Its own providers read dictionaries,
environment variables, secret files and `IConfiguration`, and its
[guides](https://github.com/runsecure/configurationresolver-dotnet/blob/main/Docs/README.md)
cover templates, tokens and `SecretBuffer<T>` in full.

## 1. Install

```bash
dotnet add package HkdfGuard.Integration.ConfigurationResolver
```

It brings in `ConfigurationResolver`. Add the package for your cache too, such as
`HkdfGuard.Cache.HashiCorpVault`.

## 2. Resolve a template

A template's key is the cache's name for the value, unchanged. For a remote cache that includes the
`secret#key` form, so `${app-config#password}` is the `password` key of the secret `app-config`.

```csharp
using ConfigurationResolver.Buffers;
using ConfigurationResolver.Readers;
using ConfigurationResolver.Resolvers;
using ConfigurationResolver.Tokens;
using HkdfGuard.Abstractions;
using HkdfGuard.Integration.ConfigurationResolver;

// secrets is any IProtectedReadOnlyCache, such as a HashiCorpVaultSecretCache.
async Task<SecretBuffer<char>> ResolveConnectionStringAsync(IProtectedReadOnlyCache secrets, CancellationToken cancellationToken)
{
    const string template = "Host=db.internal;Username=${app-config#user};Password=${app-config#password}";

    var token = new DefaultToken();
    var reader = new ConfigurationItemReader(token);
    reader.ReadKeys(template);

    var provider = new ProtectedCacheValueProvider(secrets);
    await provider.PrefetchAsync(reader, cancellationToken);

    var resolver = new ConfigurationItemResolver(token, reader, provider);
    var connectionString = new SecretBuffer<char>(capacity: 1024);
    try
    {
        resolver.Resolve(template, connectionString);
        return connectionString;
    }
    catch
    {
        connectionString.Dispose();
        throw;
    }
}
```

The resolver looks up only the keys the reader read from the template. Read the template from a
trusted source: it decides which secrets are revealed.

> **Security:** Each value is decrypted straight into the destination, or through a stack or pinned
> buffer that is zeroed once the value is copied out. It never becomes a string. If resolving fails,
> the resolver wipes the destination. Keep the result in a `SecretBuffer<T>` and hand its `Span` on;
> see ConfigurationResolver's
> [Handling secrets](https://github.com/runsecure/configurationresolver-dotnet/blob/main/Docs/secrets.md).

### Why prefetch

ConfigurationResolver's value providers are synchronous. The first time a remote cache is asked for
a secret, it fetches it, and a synchronous lookup blocks the thread until the fetch returns.
`PrefetchAsync` asks the cache for each of the reader's keys without blocking. The cache keeps
every value it fetches, encrypted, so `Resolve` then reads only from memory.

Prefetching fetches one key at a time, and a secret only once however many of its keys the
template uses. A key the cache doesn't have is skipped there and reported by `Resolve`, as
`ConfigurationKeyException` with `ConfigurationKeyError.NotFound`. For a local cache, prefetching
does nothing and you can leave it out.

## 3. Combine it with other providers

Pass several providers, highest priority first. The first one that has a key supplies its value.
Put plain values, such as a host name, in a plain provider, and the secrets in the cache:

```csharp
using ConfigurationResolver.Providers;

var resolver = new ConfigurationItemResolver(token, reader,
    new ProtectedCacheValueProvider(secrets),
    new EnvironmentVariableValueProvider());
```

Or with the builder:

```csharp
using ConfigurationResolver.Builders;

var resolver = new ConfigurationResolverBuilder()
    .WithToken(token)
    .WithReader(reader)
    .AddProtectedCache(secrets)
    .AddValueProvider(new EnvironmentVariableValueProvider())
    .Build();
```

## 4. Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` resolves templates for you, on lookup. It works like
`ProtectedCacheCollection`: you add sources, and it checks them in order. When a value it finds in
a **template source** holds items, it resolves them from every source, encrypts the result under
your key ring, and caches it. Later lookups only decrypt the cached result. A value without items,
or any value from a plain source, is answered by its source, unchanged.

Sources are added in one of two ways:

- `AddTemplateSource(source)` for a source whose values may be templates. Add this way only a
  source written by parties you trust with every secret in the collection, such as your own
  application's configuration, written by its deployment pipeline.
- `Add(source)` for a source whose values are only ever values. A value from it that happens to
  hold `${...}` is returned exactly as stored, and nothing it names is looked up. Use this for a
  shared secret store whose paths other teams or services can write to.

Both kinds answer names and supply the items a template names.

Because it is itself an `IProtectedReadOnlyCache`, anything that reads a cache can read resolved
templates without knowing they were templates:

```csharp
using HkdfGuard.Integration.ConfigurationResolver;

// keyRing is your application's KeyRing. local holds, say, the encrypted value
// "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"
// under the name "ConnectionStrings:Orders"; vault is a HashiCorpVaultSecretCache.
var secrets = new ResolvingProtectedCacheCollection(keyRing)
    .AddTemplateSource(local)
    .Add(vault);

var length = await secrets.GetMaxDecryptedLengthAsync("ConnectionStrings:Orders");
var connectionString = new char[length];
var written = await secrets.DecryptAsync("ConnectionStrings:Orders", connectionString);
```

The async members look up the template and every value it names through each source's async
members, so a remote source doesn't block a thread. Items can also come from value providers that
are asked after every source, such as environment variables for values that aren't secret:

```csharp
var secrets = new ResolvingProtectedCacheCollection(keyRing)
    .AddTemplateSource(local)
    .Add(vault)
    .AddValueProvider(new EnvironmentVariableValueProvider());
```

> **Security:** A template can name any value in any source and any value provider, so whoever can
> write a template can read, through your application, everything your application can. That is why
> only a template source's values are templates. Never add a store that other parties can write to
> with `AddTemplateSource`: a value they wrote, such as
> `https://theirs.example/?p=${platform/db-admin#password}`, would otherwise be resolved with your
> application's access and handed back with the secret inside. Added with `Add`, that value comes
> back exactly as written.

Some things to know:

- **Resolved values are kept until you invalidate them.** When a value a template uses changes,
  such as an `AddOrUpdate`, a configuration reload or a rotated remote secret, call
  `Invalidate(name)` with the template's name, or `Clear()`. The next lookup resolves it again. A
  resolution already under way when you call either doesn't cache its result.
- **Items are resolved one level deep.** An item whose value is itself a template inserts that
  template's text unresolved.
- **A template that names a missing value throws** `ConfigurationKeyException` on lookup, rather
  than reporting the template's name missing. A template that resolves to nothing is reported
  missing, as an empty value can't be cached.
- **Names match exactly**, as the sources' own names do. The cache keeps `Db` and `db` apart even
  though HkdfGuard's caches otherwise ignore ASCII case.
- **Resolved values are capped** at `MaxResolvedLength` bytes, 1 MiB by default. A longer one
  throws `InvalidOperationException`.

## Values as strings

`IValueProvider.TryGetValue` returns a value as a string, which can't be wiped. The resolver never
calls it, and `ProtectedCacheValueProvider` throws `InvalidOperationException` if anything else
does. When a caller truly needs strings, opt in:

```csharp
var provider = new ProtectedCacheValueProvider(secrets) { AllowStringValues = true };
```

The same applies to ConfigurationResolver's `ResolvingConfigurationRoot`: it works with this
provider, but it returns each resolved value as a string, so expect those to stay in memory.
