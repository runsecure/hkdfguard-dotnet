# Run the AWS KMS integration tests

`AwsKmsIntegrationTests` in `test/HkdfGuard.KeyWrapping.AwsKms.Test` make real calls to AWS KMS
through `AwsKmsKeyWrapper`. This page sets up a KMS key and a low-privilege identity for them, and
runs them from the command line and the IDE.

The other tests in the project use a fake KMS and run without any of this. The integration tests
are reported as **skipped**, never passed, until a key is configured.

They check that:

- a DEK survives a wrap and unwrap round trip;
- `GenerateAndWrapAsync` produces a wrapped DEK that reveals to 32 non-zero bytes;
- a DEK wrapped under one encryption context is refused under another;
- a tampered wrapped DEK is refused.

The tests never create, change, disable or delete a key.

## What you need

- An AWS account. The free tier covers the requests; the key itself costs about $1 a month.
- The [AWS CLI](https://aws.amazon.com/cli/), for setting up and checking credentials.
- The .NET 10 SDK.

## 1. Create a test key

Create a symmetric, encrypt-and-decrypt KMS key as in
[Wrap keys with AWS KMS, step 1](use-aws-kms.md#1-create-the-kms-key). Use a key only for tests,
never one that protects real data, and give it an alias such as `alias/hkdfguard-integration-test`
so it's easy to find.

Copy its key ARN.

## 2. Create an IAM user for the tests

Don't run the tests as the root user, and don't create an access key for root. Create an IAM user
that can use only this key:

1. In the console, open **IAM**, then **Users**, then **Create user**. Name it, for example,
   `hkdfguard-dev`.
2. Leave **Provide user access to the AWS Management Console** cleared. The tests need only an
   access key.
3. Create the user without attaching any policies.
4. Open the user, choose **Add permissions**, then **Create inline policy**. Switch to **JSON**,
   paste the policy below with your key's ARN as `Resource`, and name it `HkdfGuardKmsIntegrationTest`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext"],
       "Resource": "arn:aws:kms:us-east-2:[account id]:key/[key id]"
     }]
   }
   ```

   Replace the whole ARN with your own and leave no placeholders. Use the key ARN, not the alias
   ARN: an alias in `Resource` doesn't grant access to the key.
5. On the user's **Security credentials** tab, choose **Create access key**, then **Command Line
   Interface (CLI)**. Copy the access key ID and the secret access key. The secret is shown only
   once; if you lose it, delete the access key and create another.

## 3. Store the credentials

Run `aws configure` and enter the IAM user's access key:

```text
AWS Access Key ID [None]: AKIA...
AWS Secret Access Key [None]: ...
Default region name [None]: us-east-2
Default output format [None]: json
```

- **Access key ID** is the shorter value starting with `AKIA`. **Secret access key** is the longer one.
- **Region** is the key's region: the fourth field of its ARN.

This writes the `default` profile to `%USERPROFILE%\.aws\credentials` and `config` (`~/.aws/` on
macOS and Linux). The AWS SDK reads both files, so neither the credentials nor the region needs to
be in an environment variable.

Check that the CLI uses the IAM user and can reach the key:

```powershell
aws sts get-caller-identity
aws kms generate-data-key-without-plaintext --key-id <your-key-arn> --key-spec AES_256
```

The first command's `Arn` must end in `:user/hkdfguard-dev`. If it ends in `:root`, root
credentials are configured on this machine: run `aws configure` again with the IAM user's keys, and
remove any `login_session` line naming `:root` from the `config` file. The second command must
return a `CiphertextBlob`.

> **Security:** keep the access key only in the credentials file. Never put it in a runsettings
> file, `launchSettings.json`, `appsettings*.json` or anything else in the repository.

## 4. Point the tests at the key

The tests read the key ARN from `HKDFGUARD_TEST_AWS_KMS_KEY_ID`. Rather than set it in your shell,
put it in a runsettings file, which `dotnet test` applies to the test process only. Create
`aws.runsettings` in the repository root:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <HKDFGUARD_TEST_AWS_KMS_KEY_ID>[arn for your key]</HKDFGUARD_TEST_AWS_KMS_KEY_ID>
      <!-- <AWS_PROFILE>hkdfguard-dev</AWS_PROFILE> only if the credentials are in a named profile -->
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Replace `[arn for your key]`, brackets included, with the key ARN from step 1.

`.gitignore` excludes `*.runsettings`, so the file stays on your machine. An XML comment can't
contain `--`, so don't paste command lines into one; the test run refuses a malformed file.

## 5. Run the tests

From the command line:

```powershell
dotnet test test/HkdfGuard.KeyWrapping.AwsKms.Test --settings aws.runsettings
```

Every test should pass with none skipped:

```text
Passed!  - Failed:     0, Passed:    30, Skipped:     0, Total:    30
```

In **VS Code** with C# Dev Kit, add this to `.vscode/settings.json`, then run the tests from
Test Explorer:

```json
"dotnet.unitTests.runSettingsPath": "aws.runsettings"
```

In **Visual Studio**, choose **Test**, **Configure Run Settings**, **Select Solution Wide runsettings
File**, and pick `aws.runsettings`.

On a CI runner, set `HKDFGUARD_TEST_AWS_KMS_KEY_ID` in the job and give the job a role, for example
through GitHub's OIDC provider and `aws-actions/configure-aws-credentials`, rather than storing an
access key.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| 4 tests skipped | `HKDFGUARD_TEST_AWS_KMS_KEY_ID` isn't set in the test process | Pass `--settings aws.runsettings`, or select the file in the IDE |
| `Settings file provided does not conform to required format` | The runsettings file isn't valid XML, often `--` inside a comment | Fix the XML |
| `AccessDeniedException` | The IAM user's policy doesn't name this key, or the tests are using other credentials | Step 2's `Resource`; `aws sts get-caller-identity` |
| `NotFoundException` | The ARN is wrong, or the profile's region isn't the key's | Copy the ARN again; set the region in step 3 |
| `Unable to get IAM security credentials` or similar | The SDK found no credentials | Step 3; set `AWS_PROFILE` in the runsettings file if you used a named profile |
| `DisabledException` or `KMSInvalidStateException` | The key is disabled or pending deletion | Re-enable it, or cancel its deletion |

## When you're done

- **Deactivate the access key** on the IAM user's **Security credentials** tab when you're not
  running the tests, and delete it when you no longer need it.
- **To stop the key's monthly charge**, schedule it for deletion, signed in as an administrator.
  KMS waits 7 to 30 days before deleting it, and you can cancel during that time. Don't schedule a
  key that wrapped anything you still need.
- **Set a budget.** **Billing**, then **Budgets**, then a zero-spend or small monthly budget emails
  you if anything starts to cost money.
