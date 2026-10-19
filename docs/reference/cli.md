# `hkdfguard` command-line tool reference

`hkdfguard` is installed with each platform's native HkdfGuard package. (On macOS it is still
named `hkdfguard-v1-initialize`.) It does the jobs the .NET library deliberately can't:

- **`provision`** creates a service's KEK. Wrapping and unwrapping never create one.
- **`wrap`** turns a DEK into a key file.
- **`status`** reports a service's KEK without changing anything.
- **`retire`** deletes a KEK. Only the tool can delete one; the library has no delete.

The Windows section below was taken from the tool's own `--help` output and checked against its
behavior. The macOS section is incomplete.

- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)

## Windows

Installed at `%ProgramFiles%\HkdfGuard\v1\hkdfguard.exe`, beside `HkdfGuard.dll`.

```text
hkdfguard provision --service-name|-sn <name>
hkdfguard wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)
     [--group|-g <name>] [--force|-f]
hkdfguard retire --service-name|-sn <name> (--fingerprint|-fp <hex> | --corrupt)
     [--provider tpm|software]
hkdfguard status --service-name|-sn <name>
```

`--help`, or no arguments, shows the summary above.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, or `--help`. For `status`, a definite answer (present, absent, corrupt or unusable) |
| 1 | The command ran and failed; the reason is on standard error. For `status`, it couldn't tell (for example, access denied) |
| 2 | Usage error: unknown command, or a required option missing |

Errors are written to standard error as `error: <reason>`. A native failure names the failing
call and its meaning.

### Service names

Every command takes `--service-name`. A service name is 1 to 128 characters, each an ASCII
letter, digit or `.`; it doesn't start with `.` and doesn't contain `..`. For example,
`com.example.myapp`. Use exactly the same name in the tool and in your application
(`NativeHkdfKeyWrapperV1`, `KeyRingBuilder.WithServiceName`). The tool checks the name before
anything else: `provision --service-name bad..name` fails with
`may not start with '.' or contain ".."`.

### `provision`

```text
hkdfguard provision --service-name|-sn <name>
```

Makes sure the service's machine-wide KEK exists and passes verification. If it is missing,
`provision` creates it; if it exists, `provision` re-verifies its properties and access list. It
never wraps a DEK and never touches a file, so it is safe to run repeatedly, for example from
every deployment. It prints the KEK's fingerprint: record it, because `retire` requires it.

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
| -18 | Not authorized, for example not elevated | Run from an elevated prompt |
| -4 | The key storage provider or key couldn't be opened or created | Check the TPM is enabled, or the storage policy |
| -9 | A machine policy value, such as `KeyStoragePolicy`, is invalid | Fix the policy value |
| -64 | A `KeyUseGroups` entry is unresolvable, not a group, not on this host, or over-broad | Fix the policy entry |
| -19 | The existing KEK's access list is missing, lacks SYSTEM or Administrators, or grants an over-broad principal | Investigate before re-provisioning: the KEK may have been tampered with |

### `wrap`

```text
hkdfguard wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>)
     [--group|-g <name>] [--force|-f]
```

Wraps a DEK under the service's existing KEK and writes the result to a key file. It never creates
a KEK: run `provision` for the service first.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--key-file-path <path>` | `-kf` | Yes | Where to write the key file |
| `--service-name <name>` | `-sn` | Yes | The service whose KEK wraps the DEK |
| `--dek-stdin` | | One of these two | Read the DEK from standard input |
| `--dek-file <path>` | | One of these two | Read the DEK from a file. The file must be readable by its owner only, since it holds the plaintext DEK |
| `--group <name>` | `-g` | No | A local group allowed to read the key file, read-only: the group your application's account is in. Without it, only the file's owner can read it |
| `--force` | `-f` | No | Overwrite an existing key file |

**Input.** The DEK is exactly 32 random bytes, base64-encoded, which is 44 characters. One
trailing newline is allowed. `--dek-stdin` refuses an interactive console: pipe the DEK in.

> **Security:**
> - Never put the DEK in a command-line argument or an environment variable, where process
>   listings, shell history, CI logs and crash dumps can record it. Prefer `--dek-stdin`: a
>   `--dek-file` leaves the key on disk until it is securely deleted.
> - Don't build or hold the DEK in a PowerShell or Bash variable either: those strings can't be
>   cleared from memory. Write it to the tool's input from a byte buffer you zero afterwards. See
>   [Getting started, step 5](../getting-started.md#5-create-a-key-file) for a C# example using
>   `AesGcmPipelineDataProtector`.
> - The key file must be a real file on a local drive, reached through real folders: the tool
>   refuses links, junctions, 8.3 short names (`PROGRA~1`), and mapped or SUBST drives. Keep it in
>   a folder only administrators can write to. A key file is not a secret, but anyone who can
>   replace it decides which key your application encrypts new data with.

**Reading it back.** The .NET library reads key files through the native library
(`hkdfguard_open_file`), which applies the same rules: it refuses a key file that another account
could have written or replaced, and one that holds what looks like an unwrapped key. See
[Status codes](#status-codes) for the refusals.

Failures you may see:

| Status | Meaning | What to do |
|---|---|---|
| -17 | No KEK is provisioned for this service | Run `provision` first |
| -18 | The KEK exists, but this account may not use it | Run as an account in `HkdfGuardUsers` or a `KeyUseGroups` group |
| -1 | Invalid argument, for example a DEK that isn't 32 bytes | Check the input is 44 base64 characters |

> **TODO (maintainer):** add the error `wrap` reports for a `--group` that doesn't exist or isn't
> allowed.

### `status`

```text
hkdfguard status --service-name|-sn <name>
```

Read-only. Reports whether the service has a KEK (`present`, `absent`, `corrupt` or `unusable`),
which provider holds it, and its fingerprint. It also lists any other key under the service's
name in the key store the storage policy doesn't select. Run it from any account that can use the
key.

### `retire`

```text
hkdfguard retire --service-name|-sn <name> (--fingerprint|-fp <hex> | --corrupt) [--provider tpm|software]
```

Deletes the service's KEK. **Every DEK wrapped under it becomes permanently unrecoverable**, so
retire a KEK only after every application has moved to a new service name and no key file
wrapped under the old one is still needed. Run it elevated.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--service-name <name>` | `-sn` | Yes | The service whose KEK to delete |
| `--fingerprint <hex>` | `-fp` | One of these two | The 64 hex characters `provision` printed. Deletes only a KEK with exactly this fingerprint |
| `--corrupt` | | One of these two | Deletes a key under the service's name only if `status` reports it as corrupt: not a P-256 key at all |
| `--provider tpm\|software` | | No | Which key to delete when both key stores hold one for the service |

Each retirement is logged to the Windows Application event log as event 1004.

### Status codes

The tool reports the native library's status codes, and the .NET library reports the same codes
in its exception messages. The table is shared, number for number, by the Windows, Linux and macOS
native libraries; the full list with meanings is the `DescribeStatus` table in
[`AbstractHkdfGuardKmsLibrary.cs`](../../src/HkdfGuard.KeyWrapping.V1/Interop/AbstractHkdfGuardKmsLibrary.cs).

Reading a key file (`hkdfguard_open_file`) can fail with:

| Status | Meaning | .NET exception |
|---|---|---|
| -32 | The file, or a folder in its path, does not exist | `FileNotFoundException` |
| -33 | This account may not read the file | `UnauthorizedAccessException` |
| -34 | Not a regular file, in use by a writer, or a read failed | `IOException` |
| -35 | Shorter than a wrapped DEK | `InvalidDataException` |
| -36 | Longer than a wrapped DEK | `InvalidDataException` |
| -37 | Holds what looks like an **unwrapped** DEK: 32 raw bytes, or its hex or base64. Treat it as a key exposure | `InvalidDataException` |
| -38 | The right size, but not a valid wrapped DEK | `InvalidDataException` |
| -39 | Untrusted: a link, junction or 8.3 short name in the path, a network, mapped or SUBST drive, or a file or folder another account could write or replace | `UnauthorizedAccessException` |

## macOS

Installed system-wide at `/Library/Application Support/HkdfGuard/v1`, or per user at
`~/.hkdfguard/v1`, beside `libhkdfguard_v1.dylib`, and still named `hkdfguard-v1-initialize`. The
KEK is a Secure Enclave key, so it needs Apple silicon and macOS 13 or later.

What is known so far:

- `provision --service-name <name>` creates the service's KEK, as on Windows.
- `wrap` accepts `--dek-stdin`, as on Windows, and also `--dek-file <path>`. Prefer standard
  input: a file leaves the key on disk until it is securely deleted.
- Pass `--fingerprint <hex>` to `wrap`, so the tool refuses to write a key file under any KEK other
  than the one recorded when the service was provisioned.
- `status` and `retire --fingerprint <hex>` work as on Windows.
- Service names are matched case-insensitively on macOS.

> **TODO (maintainer):** paste the macOS `--help` output for the tool and each command, and fill in
> this section to match the Windows one: options, exit codes, where the fingerprint comes from,
> keychain modes (system and per-user), and the permissions written on a key file.

## Linux

The `hkdfguard` package installs the tool as `/usr/bin/hkdfguard`, beside `libhkdfguard.so.1`
from `libhkdfguard1`. `provision` and `wrap` take the same options as on Windows; see
`man hkdfguard` for the Linux specifics (the policy file, providers and key file permissions).
