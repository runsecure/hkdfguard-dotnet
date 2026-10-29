# Run the HashiCorp Vault transit integration tests

`HashiCorpVaultTransitIntegrationTests` in `test/HkdfGuard.KeyWrapping.HashiCorpVault.Test` make
real calls to a Vault transit secrets engine through `HashiCorpVaultTransitKeyWrapper`. This page
runs a Vault dev server in Docker, provisions two transit keys and a token that may use only them,
and runs the tests from the command line and the IDE.

The other tests in the project use a fake transit engine and run without any of this. The
integration tests are reported as **skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrapAsync` produces a wrapped DEK that reveals to 32 non-zero bytes, both generated in
  Vault (no context) and generated locally and encrypted (with one);
- a DEK wrapped under one context is refused under another, and under none;
- a DEK wrapped under one key is refused by another;
- a tampered wrapped DEK, and an invalid token, are refused;
- a crypto provider can generate and reveal its DEK through the wrapper.

The tests never create, rotate, read or delete a key.

## What you need

- Docker.
- Git Bash (on Windows) or any bash with `curl`, for the provisioning script.
- The .NET 10 SDK.

## 1. Start a Vault dev server

```bash
docker run -d --name hkdfguard-vault --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 hashicorp/vault:1.19.0
```

The image's default command is `server -dev`: unsealed, in memory, listening on plain http. Bind it
to `127.0.0.1` as above, never to every interface. The wrapper allows http only on a loopback
address.

Read the root token the server printed:

```bash
docker logs hkdfguard-vault 2>&1 | grep 'Root Token:'
```

A dev server keeps everything in memory, so a restarted container starts empty, with a new root
token. Repeat step 2 after every restart.

> The Vault cache's integration tests (`test/HkdfGuard.Cache.HashiCorpVault.Test`) can use the same
> server; they read the same `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_TOKEN` and
> `HKDFGUARD_TEST_VAULT_CACERT`, but need a token that can read their KV secret.

## 2. Provision the keys and a token

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root token> scripts/provision-vault-transit-test-key.sh
```

The script uses the root token only to provision. It:

1. enables a transit engine at `transit` if nothing is mounted there;
2. creates two `aes256-gcm96` keys, `hkdfguard-test` and `hkdfguard-test-other`;
3. writes the policy `hkdfguard-transit-test`, granting `update` (not `create`) on `encrypt`,
   `decrypt` and `datakey/wrapped` for those two keys only;
4. creates a 24-hour token with only that policy, and prints it.

So the tests run with what a real application would get, not root: they can't create a key by
naming one that doesn't exist, list keys, or touch anything else. Re-running the script is safe; it
keeps the keys and prints a new token.

Point the script only at a dev server. If yours was started with `-dev-tls`, set `VAULT_CACERT` to
its CA first, and use https below.

## 3. Point the tests at the key

Rather than set variables in your shell, put them in a runsettings file, which `dotnet test`
applies to the test process only. Create or extend `vault.runsettings` in the repository root:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <HKDFGUARD_TEST_VAULT_ADDR>http://127.0.0.1:8200</HKDFGUARD_TEST_VAULT_ADDR>
      <HKDFGUARD_TEST_VAULT_TOKEN>[token the script printed]</HKDFGUARD_TEST_VAULT_TOKEN>
      <HKDFGUARD_TEST_VAULT_TRANSIT_KEY>hkdfguard-test</HKDFGUARD_TEST_VAULT_TRANSIT_KEY>
      <HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY>hkdfguard-test-other</HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Replace `[token the script printed]`, brackets included, with the token from step 2.

| Variable | Needed | Meaning |
|---|---|---|
| `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` | Yes | The transit key to wrap under; without it every test is skipped |
| `HKDFGUARD_TEST_VAULT_TOKEN` | Yes | A token allowed `update` on that key's `encrypt`, `decrypt` and `datakey/wrapped` |
| `HKDFGUARD_TEST_VAULT_ADDR` | No | Vault's address; default `http://127.0.0.1:8200` |
| `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` | No | A second key, for the cross-key test; that test is skipped without it |
| `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` | No | The transit mount; default `transit` |
| `HKDFGUARD_TEST_VAULT_CACERT` | No | The full path of a CA to trust, for a server started with TLS |

`.gitignore` excludes `*.runsettings`, so the file stays on your machine. An XML comment can't
contain `--`, so don't paste command lines into one; the test run refuses a malformed file.

## 4. Run the tests

From the command line:

```powershell
dotnet test test/HkdfGuard.KeyWrapping.HashiCorpVault.Test --settings vault.runsettings
```

Every test should pass with none skipped:

```text
Passed!  - Failed:     0, Passed:   128, Skipped:     0, Total:   128
```

In **VS Code** with C# Dev Kit, add this to `.vscode/settings.json`, then run the tests from
Test Explorer:

```json
"dotnet.unitTests.runSettingsPath": "vault.runsettings"
```

In **Visual Studio**, choose **Test**, **Configure Run Settings**, **Select Solution Wide runsettings
File**, and pick `vault.runsettings`.

On a CI runner, start the same container as a service, run the provisioning script with the root
token you gave it (`-e VAULT_DEV_ROOT_TOKEN_ID=...`), and pass the printed token to the test step.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 8 tests skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_KEY` isn't set in the test process | Pass `--settings vault.runsettings`, or select the file in the IDE |
| 1 test skipped | `HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY` isn't set | Set it to `hkdfguard-test-other` |
| `403 Forbidden` ... `permission denied` | The token expired (24 hours), or the container restarted and the token is gone | Step 2 again, and update the runsettings file |
| `400 BadRequest` ... `encryption key not found` | The container restarted and the keys are gone, or the key name is wrong | Step 2 again |
| `no answer within`, or connection refused | The container isn't running, or isn't on `127.0.0.1:8200` | `docker ps`; `docker start hkdfguard-vault`, then step 2 |
| `must be https` | The address isn't loopback and isn't https | Use `127.0.0.1`, or https with `HKDFGUARD_TEST_VAULT_CACERT` |
| `Settings file provided does not conform to required format` | The runsettings file isn't valid XML, often `--` inside a comment | Fix the XML |

## When you're done

```bash
docker rm -f hkdfguard-vault
```

Nothing survives: the server kept its keys, policy and tokens in memory.
