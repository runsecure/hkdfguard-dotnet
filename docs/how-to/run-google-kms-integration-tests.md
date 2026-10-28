# Run the Google Cloud KMS integration tests

`GoogleKmsIntegrationTests` in `test/HkdfGuard.KeyWrapping.GoogleKms.Test` make real calls to
Google Cloud KMS through `GoogleKmsKeyWrapper`. This page sets up a test key, and runs the tests
from the command line and the IDE.

The other tests in the project use an in-memory fake Cloud KMS and run without any of this. The
integration tests are reported as **skipped**, never passed, until the key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrapAsync` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a wrapped DEK made under one context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change or destroy a key.

## What you need

- A Google Cloud project with billing enabled. Cloud KMS charges a small monthly fee per active key
  version and a fraction of a cent per test run; see [Cloud KMS pricing](https://cloud.google.com/kms/pricing).
- The [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) (`gcloud`).
- The .NET 10 SDK.

## 1. Sign in

Sign in twice: once for `gcloud` itself, and once for Application Default Credentials (ADC),
which the tests use:

```powershell
gcloud auth login
gcloud auth application-default login
```

## 2. Choose the project

```powershell
$project = "[project id]"
$loc     = "us-east1"
$ring    = "[key ring name]"
$key     = "[key name]"

gcloud config set project $project
gcloud auth application-default set-quota-project $project
gcloud services enable cloudkms.googleapis.com
```

Use a project for tests only, never one that protects real data. The quota project tells Google
which project to bill your ADC's API calls to; without it, calls can fail with `PermissionDenied`.

## 3. Create the key ring and key

```powershell
gcloud kms keyrings create $ring --location $loc
gcloud kms keys create $key --keyring $ring --location $loc --purpose encryption --protection-level software
```

A software key is enough for tests. Key rings can't be deleted, so pick a name you don't mind
keeping.

## 4. Give yourself access

As the project's owner you can manage the key, but owner doesn't include using it. Grant yourself
**Cloud KMS CryptoKey Encrypter/Decrypter** on the test key:

```powershell
$me = gcloud config get-value account

gcloud kms keys add-iam-policy-binding $key --keyring $ring --location $loc `
  --member "user:$me" --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

> **Security:** encrypt and decrypt together are fine for your own identity on a test key. A
> deployed application must have decrypt only; see the role table in
> [Wrap keys with Google Cloud KMS](use-google-kms.md#2-grant-each-identity-only-what-it-calls).

## 5. Fill in google.runsettings

The tests read the key's resource name from `HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME`. Rather than set
it in your shell, the repository root has a `google.runsettings` file that `dotnet test` applies to
the test process only:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME>projects/[project id]/locations/us-east1/keyRings/[key ring name]/cryptoKeys/[key name]</HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Replace `[project id]`, `[key ring name]` and `[key name]`, brackets included, with the names from
steps 2 and 3, and `us-east1` if you chose another location. If the file isn't there, create it
with the content above.

- **Name the key, not a version.** The wrapper refuses `.../cryptoKeyVersions/1`.
- **No credentials go in the file.** ADC signs in with your `gcloud auth application-default login`.
- **The file stays on your machine.** `.gitignore` excludes `*.runsettings`.
- **An XML comment can't contain `--`**, so don't paste command lines into one; the test run
  refuses a malformed file.

Check the name before running the tests:

```powershell
gcloud kms keys describe "projects/[project id]/locations/us-east1/keyRings/[key ring name]/cryptoKeys/[key name]" --format "value(purpose)"
```

It must print `ENCRYPT_DECRYPT`.

## 6. Run the tests

From the command line:

```powershell
dotnet test test/HkdfGuard.KeyWrapping.GoogleKms.Test --settings google.runsettings
```

Every test should pass, with none skipped.

In **VS Code** with C# Dev Kit, add this to `.vscode/settings.json`, then run the tests from Test
Explorer:

```json
"dotnet.unitTests.runSettingsPath": "google.runsettings"
```

That setting takes one file. To run the AWS KMS, Azure Key Vault and Cloud KMS tests together from
the IDE, put every set of variables in one runsettings file and point the setting at it.

In **Visual Studio**, choose **Test**, **Configure Run Settings**, **Select Solution Wide runsettings
File**, and pick `google.runsettings`.

On a CI runner, set the variable in the job and sign in with Workload Identity Federation (for
example GitHub's OIDC provider and `google-github-actions/auth`) rather than storing a service
account key.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 4 tests skipped | The variable isn't set in the test process | Pass `--settings google.runsettings`, or select the file in the IDE |
| `Settings file provided does not conform to required format` | The runsettings file isn't valid XML, often `--` inside a comment | Fix the XML |
| `... isn't a key's resource name. Replace the placeholders in google.runsettings` | A placeholder is still in the file, or the name is malformed | Step 5 |
| `PermissionDenied` naming `useToEncrypt` or `useToDecrypt` | The role binding is missing or on another key | Step 4; check with `gcloud kms keys get-iam-policy $key --keyring $ring --location $loc` |
| `PermissionDenied` naming a quota project, or the API | No quota project, or the API isn't enabled | Step 2 |
| `NotFound` | A name in the file is wrong | Step 5's check command |
| `Your default credentials were not found` (inner) | ADC isn't set up | `gcloud auth application-default login` |

## When you're done

Key rings and keys can't be deleted, but a key with no active versions costs nothing. Destroy the
test key's versions:

```powershell
gcloud kms keys versions list --key $key --keyring $ring --location $loc
gcloud kms keys versions destroy 1 --key $key --keyring $ring --location $loc
```

A destroyed version is kept, restorable, for its scheduled-destruction period (30 days by default),
then destroyed for good.
