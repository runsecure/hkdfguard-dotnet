# `hkdfguard-v1-initialize` reference

`hkdfguard-v1-initialize` is installed with each platform's native HkdfGuard package. It does the
two jobs the .NET library deliberately can't:

- **`provision`** creates a service's KEK. Wrapping and unwrapping never create one.
- **`wrap`** turns a DEK into a key file.

The Windows section below was taken from the tool's own `--help` output and checked against its
behavior. The macOS section is incomplete.

- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)

## Windows

Installed at `%ProgramFiles%\HkdfGuard\v1\hkdfguard-v1-initialize.exe`, beside `HkdfGuardV1.dll`.

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> --dek-stdin --group|-g <name> [--force|-f]
```

`--help` after a command shows that command's help. `--help` alone, or no arguments, shows the
summary above.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, or `--help` |
| 1 | The command ran and failed; the reason is on standard error |
| 2 | Usage error: unknown command, or a required option missing |

Errors are written to standard error as `error: <reason>`. A native failure names the failing
call and its meaning, for example:

```text
error: hkdfguard_create_kek failed: this KEK exists, but this account is not authorized to use it (creating a new KEK requires an elevated process; this account may lack rights)
```

### Service names

Every command takes `--service-name`. A service name is 1 to 128 characters, each an ASCII
letter, digit or `.`; it doesn't start with `.` and doesn't contain `..`. For example,
`com.example.myapp`. Use exactly the same name in the tool and in your application
(`NativeHkdfKeyWrapperV1`, `KeyRingBuilder.WithServiceName`).

> **TODO (maintainer):** `provision --service-name bad..name` currently fails with the
> "not authorized" message above instead of rejecting the name. Either fix the tool to validate
> the name first, or document what it does.

### `provision`

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
```

Makes sure the service's machine-wide KEK exists and passes verification. If it is missing,
`provision` creates it; if it exists, `provision` re-verifies its properties and access list. It
never wraps a DEK and never touches a file, so it is safe to run repeatedly, for example from
every deployment.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--service-name <name>` | `-sn` | Yes | The service whose KEK to create or verify |

**Run it elevated.** Creating a machine-wide KEK needs administrator rights.

The KEK is a non-exportable P-256 key in the Microsoft Platform Crypto Provider (the TPM), or in
the Microsoft Software Key Storage Provider when no TPM is available.

> **TODO (maintainer):** describe:
> - how the storage provider is chosen, and how `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy`
>   changes that (its value names and allowed values);
> - the access list a new KEK gets, and how `HKLM\Software\Policies\HkdfGuard\KeyUseGroups`
>   adds groups to it (format, and what counts as "over-broad");
> - whether the installer creates `HkdfGuardUsers`, and what a KEK grants it.

Failures you may see:

| Status | Meaning | What to do |
|---|---|---|
| -13 | Not authorized, for example not elevated | Run from an elevated prompt |
| -3 | The key storage provider or key couldn't be opened or created | Check the TPM is enabled, or the storage policy |
| -9 | `KeyStoragePolicy` is invalid | Fix the policy value |
| -10 | A `KeyUseGroups` entry is unresolvable, not a group, or over-broad | Fix the policy entry |
| -14 | The existing KEK's access list is missing, lacks SYSTEM or Administrators, or grants an over-broad principal | Investigate before re-provisioning: the KEK may have been tampered with |

### `wrap`

```text
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> --dek-stdin --group|-g <name> [--force|-f]
```

Wraps a DEK under the service's existing KEK and writes the result to a key file. It never creates
a KEK: run `provision` for the service first.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--key-file-path <path>` | `-kf` | Yes | Where to write the key file |
| `--service-name <name>` | `-sn` | Yes | The service whose KEK wraps the DEK |
| `--dek-stdin` | | Yes | Read the DEK from standard input. Currently the only way to supply it |
| `--group <name>` | `-g` | Yes | The local group allowed to read the key file: the group your application's account is in |
| `--force` | `-f` | No | See the TODO below |

**Input.** Standard input carries the DEK: exactly 32 random bytes, base64-encoded, which is 44
characters.

> **TODO (maintainer):** confirm:
> - what `--force` does (presumably: overwrite an existing key file, which `wrap` otherwise refuses);
> - the exact permissions written on the key file;
> - whether `wrap` must run elevated;
> - whether a trailing newline on standard input is accepted.

> **Security:**
> - Pass the DEK only on standard input. Never put it in a command-line argument or an
>   environment variable, where process listings, shell history, CI logs and crash dumps can
>   record it.
> - Don't build or hold the DEK in a PowerShell or Bash variable either: those strings can't be
>   cleared from memory. Write it to the tool's input from a byte buffer you zero afterwards. See
>   [Getting started, step 5](../getting-started.md#5-create-a-key-file) for a C# example using
>   `AesGcmPipelineDataProtector`.
> - Keep key files in a folder only administrators can write to. A key file is not a secret, but
>   anyone who can replace it decides which key your application encrypts new data with.

Failures you may see:

| Status | Meaning | What to do |
|---|---|---|
| -12 | No KEK is provisioned for this service | Run `provision` first |
| -13 | The KEK exists, but this account may not use it | Run as an account in `HkdfGuardUsers` or a `KeyUseGroups` group |
| -1 | Invalid argument, for example a DEK that isn't 32 bytes | Check the standard input is 44 base64 characters |

> **TODO (maintainer):** add the error `wrap` reports for a `--group` that doesn't exist or isn't
> allowed.

### Status codes

The tool reports the native library's status codes. The full list, with meanings, is the
`DescribeStatus` table in
[`WindowsHkdfGuardKmsLibrary.cs`](../../src/HkdfGuard.KeyWrapping.V1/Interop/WindowsHkdfGuardKmsLibrary.cs).
The .NET library reports the same codes in its `CryptographicException` messages.

## macOS

Installed system-wide at `/Library/Application Support/HkdfGuard/v1`, or per user at
`~/.hkdfguard/v1`, beside `libhkdfguard_v1.dylib`. The KEK is a Secure Enclave key, so it needs
Apple silicon and macOS 13 or later.

What is known so far:

- `provision --service-name <name>` creates the service's KEK, as on Windows.
- `wrap` accepts `--dek-stdin`, as on Windows, and also `--dek-file <path>`. Prefer standard
  input: a file leaves the key on disk until it is securely deleted.
- Pass `--fingerprint <hex>` to `wrap`, so the tool refuses to write a key file under any KEK other
  than the one recorded when the service was provisioned.
- Service names are matched case-insensitively on macOS.

> **TODO (maintainer):** paste the macOS `--help` output for the tool and each command, and fill in
> this section to match the Windows one: options, exit codes, where the fingerprint comes from,
> keychain modes (system and per-user), and the permissions written on a key file.

## Linux

Not released yet. The .NET library's Linux binding exists, but no native package or provisioning
tool is published.
