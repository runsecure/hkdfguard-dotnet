# Getting started

This tutorial takes one Windows machine from nothing to encrypting and decrypting with a key
protected by the TPM. It then replaces that in-memory key with a durable key file, which is what a
real deployment uses.

It takes about 20 minutes. You need:

- Windows 10 or 11, or Windows Server 2019 or later, with administrator rights for one step.
- The .NET 10 SDK.
- The HkdfGuard native package for Windows.

macOS and Linux work the same way with different install paths and tool options; see the
[CLI reference](reference/cli.md#macos) for macOS and its [Linux section](reference/cli.md#linux).

## How the pieces fit

HkdfGuard never holds your master key. There are two keys:

- The **KEK** (key-encryption key) lives in the TPM, or in the Windows software key store when
  there is no TPM. It never leaves it. Each KEK is identified by a **service name**, such as
  `com.example.myapp`.
- A **DEK** (data encryption key) is what actually encrypts your data, with AES-256-GCM. On disk
  it exists only *wrapped*, encrypted under the KEK. Your process asks the native library to unwrap
  it at startup and holds it in memory that is zeroed when you're done.

Two separate things are installed:

| Part | Where it comes from | What it does |
|---|---|---|
| The .NET libraries | NuGet, or a project reference | Everything your code calls |
| `HkdfGuard.dll` and `hkdfguard.exe` | The HkdfGuard native package, installed to `%ProgramFiles%\HkdfGuard\v1` | Hold and use the KEK |

The .NET library loads `HkdfGuard.dll` only from that folder, and only after checking its
folder permissions and its signature. It never searches `PATH` or your application folder.

## 1. Install the native package

Run the HkdfGuard installer as an administrator.

> **TODO (maintainer):** give the installer's file name and where to download it, and say whether
> it creates the `HkdfGuardUsers` group.

Check that it installed:

```powershell
Get-AuthenticodeSignature "$env:ProgramFiles\HkdfGuard\v1\HkdfGuard.dll" | Select-Object Status, SignerCertificate
```

`Status` must be `Valid`.

## 2. Provision a KEK for your service

Choose a service name. It is 1 to 128 ASCII letters, digits or dots, doesn't start with a dot,
and never contains `..`. Reverse-DNS style works well: `com.example.myapp`. Hyphens are not
allowed.

Open PowerShell **as administrator** and run:

```powershell
& "$env:ProgramFiles\HkdfGuard\v1\hkdfguard.exe" provision --service-name com.example.myapp
```

This creates the KEK in the TPM. Running it again is safe: if the KEK already exists, the command
only checks that its properties and access list are still correct.

Then let the account your application runs as use the KEK by adding it to the `HkdfGuardUsers`
group:

```powershell
Add-LocalGroupMember -Group HkdfGuardUsers -Member "$env:USERDOMAIN\$env:USERNAME"
```

Sign out and back in, so your session picks up the new group.

> **Security:** add only the accounts that run your application. Any member of the group can use
> every KEK the group is allowed to use.

## 3. Encrypt and decrypt with an in-memory key

Create a console app and add the libraries:

```powershell
dotnet new console -n HkdfGuardDemo
cd HkdfGuardDemo
dotnet add package HkdfGuard.DataEncryptionKey
dotnet add package HkdfGuard.CryptoProvider.AesGcm256
dotnet add package HkdfGuard.KeyWrapping.V1
```

> **TODO (maintainer):** confirm these package IDs once the packages are published.

Replace `Program.cs` with:

```csharp
using HkdfGuard.CryptoProvider.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.KeyWrapping.V1;

await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("com.example.myapp"))
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(60)
    .WithEphemeralKey(version: 1)
    .BuildAsync();

var protector = ring.CreateProtector("customer-notes");
string encrypted = protector.Encrypt("The launch code is 0000");
Console.WriteLine(encrypted);

Span<char> buffer = stackalloc char[protector.GetMaxDecryptedLength(encrypted)];
int written = protector.Decrypt(encrypted, buffer);
Console.WriteLine(buffer[..written].ToString());
```

Run it with `dotnet run`. You should see something like:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `BuildAsync` asked the native library to generate a fresh DEK and wrap it under your KEK. It
  then unwrapped it into protected memory. The plaintext DEK was never on disk.
- `enc::v1::...` is the stored form: `v1` is the key version, and the rest is the AES-GCM
  ciphertext in base64.
- `"customer-notes"` is the protector's **purpose**. It is bound into every value, so a value
  encrypted by one protector never decrypts under a protector with another name.
- `WithKeyRefreshInterval(60)` makes the library re-check the KEK every 60 seconds. If the KEK
  stops being available (it was deleted, or your account lost access), encryption stops after
  three failed checks, about three minutes, until access returns.

**The catch:** an ephemeral key exists only in this process. Run the program again and the first
value can't be decrypted, because that key is gone. That's right for short-lived data such as
session tokens. Data you store needs a key file.

## 4. Understand key files

A **key file** holds one wrapped DEK. It is useless without the KEK, so it is not a secret in the
usual sense, but its permissions still matter. Anyone who can replace it controls the key your
application encrypts new data with.

You create a key file once per release, or per key rotation, with `hkdfguard wrap`. The tool
reads the DEK on standard input, wraps it under the service's KEK, and writes the file so that
only its owner can read and write it. Its `--group` option adds a local group whose members can
read the file too: the group your application's account is in.

Your application reads the key file through the native library, which refuses one that another
account could have written or replaced. Keep key files in a folder only administrators and
deployers can write to, reached through real folders (no links, junctions or short names like
`PROGRA~1`), and never under `C:\ProgramData`.

Whether `wrap` needs elevation, and which accounts may use a service's KEK, is up to the native
library on each platform; see `hkdfguard wrap --help` and the native library's documentation.

Where does the DEK come from? In a deployment pipeline, use `AesGcmPipelineDataProtector`. It
generates a key in memory and can encrypt your configuration secrets under it. At the end of the
pipeline you pass that same key to `wrap`. This tutorial skips the configuration secrets and only
creates the file.

## 5. Create a key file

Add this method to your program. It generates a DEK, passes it to `wrap` on standard input, and
zeroes every copy it controls:

```csharp
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using HkdfGuard.DataEncryptionKey.FormatProvider;

static void CreateKeyFile(string toolPath, string serviceName, string keyFilePath, string group)
{
    using var protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), keyVersion: 1);

    var start = new ProcessStartInfo(toolPath) { RedirectStandardInput = true, UseShellExecute = false };
    foreach (var arg in new[] { "wrap", "--service-name", serviceName, "--key-file-path", keyFilePath, "--group", group, "--dek-stdin" })
        start.ArgumentList.Add(arg);

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
    if (tool.ExitCode != 0)
        throw new InvalidOperationException($"hkdfguard wrap failed with exit code {tool.ExitCode}.");
}
```

Before you call it on Windows, prepare the folder it writes to. The native library refuses a key
file anywhere under `C:\ProgramData`, where every user may create entries, and in a folder created
directly under `C:\` with its default permissions. From an elevated PowerShell, give the key files
a folder of their own, with inherited permissions removed:

```powershell
New-Item -ItemType Directory -Force C:\HkdfGuardKeys\myapp | Out-Null
icacls C:\HkdfGuardKeys /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" "HkdfGuardDeployers:(OI)(CI)M"
icacls C:\HkdfGuardKeys /setowner "*S-1-5-32-544" /T
```

Then make the call from an elevated prompt, or as a member of `HkdfGuardDeployers`. Under the
production security model, the Windows default, `wrap` refuses any other account, and the library
doesn't trust a key file that the application's own account wrote. The native library's
[administration guide](https://github.com/runsecure/hkdfguard-native-windows/blob/main/docs/admin-guide.md#where-to-keep-key-files)
explains both rules.

Call it once:

```csharp
CreateKeyFile(
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"HkdfGuard\v1\hkdfguard.exe"),
    serviceName: "com.example.myapp",
    keyFilePath: @"C:\HkdfGuardKeys\myapp\v1.key",
    group: "HkdfGuardUsers");
```

> **Security:** pass the DEK on standard input, as above. Never pass it as a command-line argument
> or an environment variable: process listings, shell history, CI logs and crash dumps record
> those. Don't build it in a PowerShell or Bash variable either. Those strings can't be cleared
> from memory.

## 6. Use the key file

Replace `WithEphemeralKey` with `WithKeyFile`:

```csharp
await using var ring = await new KeyRingBuilder()
    .WithServiceName("com.example.myapp")
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("com.example.myapp"))
    .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
    .WithKeyRefreshInterval(60)
    .WithKeyFile(version: 1, pathToFile: @"C:\HkdfGuardKeys\myapp\v1.key")
    .BuildAsync();
```

Now values survive a restart: encrypt, run the program again, and decrypt the earlier value.

The `version` you give `WithKeyFile` is what appears as `v1` in every value. When you rotate, add a
`v2.key` with `WithKeyFile(version: 2, ...)`. New values use the highest version, and older values
still decrypt as long as their key file stays registered.

## If something goes wrong

| You see | Cause | Fix |
|---|---|---|
| `DllNotFoundException` naming `%ProgramFiles%\HkdfGuard\v1` | The native package isn't installed | Step 1 |
| `SecurityException` | The installed DLL, or a folder above it, failed verification: wrong signature, or writable by non-administrators | Reinstall the native package; don't change that folder's permissions |
| `CryptographicException` ... `status -17` | No KEK is provisioned for this service name | Step 2, with the same service name |
| `CryptographicException` ... `status -18` | The KEK exists, but this account may not use it | Add the account to `HkdfGuardUsers`, then sign out and in |
| `CryptographicException` ... `status -16` | The key file was wrapped under a different service's KEK | Use the service name the file was created with |
| `CryptographicException` ... `status -11` | The key file was altered | Restore it from your deployment artifacts |
| `UnauthorizedAccessException` ... `status -39` | The key file's path isn't trusted: a link, junction or short name in it, or a file or folder another account can write | Move the file to a folder only administrators can write to, and use its full path |
| `InvalidDataException` ... `status -37` | The "key file" holds what looks like an **unwrapped** key | Treat the key as exposed: replace it, and create the file with `wrap` |
| `InvalidDataException` ... `status -35`, `-36` or `-38` | The file isn't a key file: wrong size, or not a valid wrapped key | Check the path; recreate it with `wrap` |
| `ArgumentException` about the service name | The name breaks the rule in step 2 | Use letters, digits and dots only |

Every native error message includes the status code and its meaning.

## Next steps

- [`hkdfguard` reference](reference/cli.md): every command and option.
- The README's *Key rotation*, *Pipeline protection* and *Diagnostics* sections, until their how-to
  pages are written.
