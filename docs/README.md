# HkdfGuard documentation

Pick the page for what you're doing.

**New to HkdfGuard:** start with [Getting started](getting-started.md). It takes one Windows
machine from nothing to encrypting and decrypting with a TPM-protected key, then to a durable key
file.

**Running HkdfGuard in production** (installing, provisioning, creating key files): see the
[`hkdfguard` reference](reference/cli.md).

## Map

| Kind | Page | Status |
|---|---|---|
| Tutorial | [Getting started](getting-started.md) | Draft |
| How-to | Provision a service on each platform | Planned |
| How-to | Create key files in a deployment pipeline | Planned |
| How-to | Rotate keys | Planned (see the README's *Key rotation* section for now) |
| How-to | Use HkdfGuard with dependency injection and `IConfiguration` | Planned |
| How-to | Troubleshoot | Planned |
| Reference | [`hkdfguard`](reference/cli.md) | Draft (Windows complete; macOS pending) |
| Reference | Native status codes | Planned |
| Reference | `HkdfGuardOptions` / configuration schema | Planned |
| Reference | API | Planned (generated from XML doc comments) |
| Explanation | Key hierarchy: KEK, wrapped DEK, AES-GCM | Planned (see the README's *Key concepts*) |
| Explanation | Threat model and fail-closed behavior | Planned |
| Explanation | How the native library is verified before loading | Planned (see the README's *Getting started* section) |

## Conventions

- Every code sample in these pages compiles against the current source. When you change one,
  build it before committing.
- Facts about `hkdfguard` come from its own `--help` output and observed behavior.
  Anything not yet confirmed is marked **TODO (maintainer)**; search for that string before
  publishing.
- Security rules are stated as rules, at the step where they apply, in a block that starts with
  **Security:**.
