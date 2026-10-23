# Run the Azure Key Vault integration tests

`AzureKeyVaultIntegrationTests` in `test/HkdfGuard.KeyWrapping.AzureKeyVault.Test` make real calls
to Azure Key Vault through `AzureKeyVaultKeyWrapper`. This page sets up a test vault with the two
keys the wrapper needs, and runs the tests from the command line and the IDE.

The other tests in the project use an in-memory fake vault and run without any of this. The
integration tests are reported as **skipped**, never passed, until both keys are configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrapAsync` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a wrapped DEK made under one context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change or delete a key.

## What you need

- An Azure subscription. A free account works; a test run is about 20 Key Vault operations, a
  fraction of a cent, and software-protected keys have no monthly fee.
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli).
- The .NET 10 SDK.

## 1. Sign in

```powershell
az login
az account show --query "{subscription:name, tenant:tenantId, user:user.name}" -o table
```

If the subscription isn't the one you want, run `az account set --subscription "<name or id>"`.

## 2. Create a test vault

Use a vault only for tests, never one that protects real data. Vault names are globally unique:
3 to 24 letters, digits and hyphens.

```powershell
$rg    = "hkdfguard-test-rg"
$vault = "[key vault name]"
$loc   = "eastus2"

az group create --name $rg --location $loc
az keyvault create --name $vault --resource-group $rg --location $loc `
  --enable-rbac-authorization true --retention-days 7
```

Purge protection is left off so the test vault can be deleted completely afterwards. A vault that
protects real data should have it on; see
[Wrap keys with Azure Key Vault](use-azure-key-vault.md#1-create-the-keys).

## 3. Give yourself access

Creating keys and running the tests both need Key Vault's crypto operations. Assign yourself
**Key Vault Crypto Officer** on the test vault:

```powershell
$me      = az ad signed-in-user show --query id -o tsv
$vaultId = az keyvault show --name $vault --query id -o tsv

az role assignment create --assignee $me --role "Key Vault Crypto Officer" --scope $vaultId
```

A role assignment takes a minute or two to apply.

> **Security:** Crypto Officer includes `sign`, which is fine for your own test identity on a test
> vault. A deployed application must never have `sign` on the signing key; see the role table in
> [Wrap keys with Azure Key Vault](use-azure-key-vault.md#2-grant-each-identity-only-what-it-calls).

## 4. Create the two keys

An RSA key to wrap, and an EC P-256 key to sign, each allowed only its own two operations:

```powershell
az keyvault key create --vault-name $vault --name "[key vault wrap key name]" --kty RSA --size 2048 --ops wrapKey unwrapKey
az keyvault key create --vault-name $vault --name "[key vault sign key name]" --kty EC --curve P-256 --ops sign verify
```

If either fails with `Forbidden`, the role from step 3 hasn't applied yet; wait a minute and run it
again.

## 5. Fill in azure.runsettings

The tests read the two key identifiers from `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID` and
`HKDFGUARD_TEST_AZURE_SIGN_KEY_ID`. Rather than set them in your shell, the repository root has an
`azure.runsettings` file that `dotnet test` applies to the test process only:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <HKDFGUARD_TEST_AZURE_WRAP_KEY_ID>https://[key vault name].vault.azure.net/keys/[key vault wrap key name]</HKDFGUARD_TEST_AZURE_WRAP_KEY_ID>
      <HKDFGUARD_TEST_AZURE_SIGN_KEY_ID>https://[key vault name].vault.azure.net/keys/[key vault sign key name]</HKDFGUARD_TEST_AZURE_SIGN_KEY_ID>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Replace `[key vault name]`, `[key vault wrap key name]` and `[key vault sign key name]`, brackets
included, with the names from steps 2 and 4. If the file isn't there, create it with the content
above.

- **Leave the version off.** The wrapper then uses each key's current version, as it would in
  production.
- **No credentials go in the file.** `DefaultAzureCredential` signs in with your `az login`.
- **The file stays on your machine.** `.gitignore` excludes `*.runsettings`.
- **An XML comment can't contain `--`**, so don't paste command lines into one; the test run
  refuses a malformed file.

Check the identifiers before running the tests:

```powershell
az keyvault key show --id "https://[key vault name].vault.azure.net/keys/[key vault wrap key name]" --query "key.kty" -o tsv
az keyvault key show --id "https://[key vault name].vault.azure.net/keys/[key vault sign key name]" --query "key.crv" -o tsv
```

The first must print `RSA`, the second `P-256`.

## 6. Run the tests

From the command line:

```powershell
dotnet test test/HkdfGuard.KeyWrapping.AzureKeyVault.Test --settings azure.runsettings
```

Every test should pass, with none skipped.

In **VS Code** with C# Dev Kit, add this to `.vscode/settings.json`, then run the tests from Test
Explorer:

```json
"dotnet.unitTests.runSettingsPath": "azure.runsettings"
```

That setting takes one file. To run the AWS KMS and Azure Key Vault tests together from the IDE,
put both sets of variables in one runsettings file and point the setting at it.

In **Visual Studio**, choose **Test**, **Configure Run Settings**, **Select Solution Wide runsettings
File**, and pick `azure.runsettings`. Sign Visual Studio into the same account as `az login`:
`DefaultAzureCredential` tries Visual Studio's account first.

On a CI runner, set the two variables in the job and sign in with a federated identity (for
example GitHub's OIDC provider and `azure/login`) rather than storing a client secret.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 4 tests skipped | One or both variables aren't set in the test process | Pass `--settings azure.runsettings`, or select the file in the IDE |
| `Settings file provided does not conform to required format` | The runsettings file isn't valid XML, often `--` inside a comment | Fix the XML |
| `... isn't a key identifier. Replace the placeholders in azure.runsettings` | A placeholder is still in the file | Step 5 |
| `Forbidden (HTTP 403)` or `ForbiddenByRbac` | The role assignment hasn't applied, or is on another vault | Wait; check with `az role assignment list --assignee $me --scope $vaultId -o table` |
| `KeyNotFound (HTTP 404)` | A vault or key name in the file is wrong | Step 5's check commands |
| `AuthenticationFailedException` or a tenant error | `DefaultAzureCredential` picked an account in another tenant | Sign Visual Studio into the same account, or set `AZURE_TENANT_ID` in the runsettings file |
| `The signing key must be an EC P-256 key` | The two identifiers are swapped, or the signing key is another curve | Step 5's check commands |

## When you're done

Delete the resource group, then purge the vault so its name can be reused:

```powershell
az group delete --name $rg --yes
az keyvault purge --name $vault --location $loc
```

Until it's purged, a deleted vault is kept for its 7-day retention period, at no cost.
