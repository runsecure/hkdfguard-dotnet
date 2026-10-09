<#
.SYNOPSIS
    Provisions the KEK the native integration tests use on Windows.

.DESCRIPTION
    Runs the installed HkdfGuard tool's "provision" command for the test service name, which creates
    a machine-wide KEK for it in the Platform Crypto Provider (TPM), or re-verifies it if it already
    exists. Safe to run repeatedly. It never wraps a DEK and never touches a key file.

    Must run from an elevated PowerShell: creating a machine-wide KEK requires administrator rights.

    Before running the tool, the script checks that it is the signed HkdfGuard tool from the fixed
    install location - the same publisher the library's own loader requires - so an elevated session
    never runs an impostor.

    Once provisioned, the native tests in HkdfGuard.KeyWrapping.V1.Test run automatically on this
    machine instead of being reported as skipped:

        dotnet test test/HkdfGuard.KeyWrapping.V1.Test

.PARAMETER ServiceName
    The service whose KEK to provision. Defaults to the name the tests use.

.EXAMPLE
    # From an elevated PowerShell at the repository root:
    ./scripts/provision-windows-test-key.ps1
#>
[CmdletBinding()]
param(
    [ValidatePattern('^(?!\.)(?!.*\.\.)[A-Za-z0-9.]{1,128}$')]
    [string] $ServiceName = 'com.hkdfguard.native.windows.test'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The same publisher WindowsNativeLibraryLoader.ExpectedPublisher requires of HkdfGuardV1.dll.
$ExpectedPublisher = 'CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US'

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'This script provisions a Windows KEK and must run on Windows.'
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Creating a machine-wide KEK requires an elevated process. Re-run this script from an elevated PowerShell ("Run as administrator").'
}

# The known-folder location, not the ProgramFiles environment variable, which any process can change.
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$tool = Join-Path $programFiles 'HkdfGuard\v1\hkdfguard-v1-initialize.exe'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
    throw "The HkdfGuard provisioning tool is not installed at '$tool'. Install the HkdfGuard native package first."
}

$signature = Get-AuthenticodeSignature -LiteralPath $tool
if ($signature.Status -ne 'Valid') {
    throw "'$tool' does not carry a valid Authenticode signature (status: $($signature.Status)). Refusing to run it elevated."
}
if ($signature.SignerCertificate.Subject -ne $ExpectedPublisher) {
    throw "'$tool' is signed by '$($signature.SignerCertificate.Subject)', not the HkdfGuard publisher. Refusing to run it elevated."
}

Write-Host "Provisioning the KEK for service '$ServiceName'..."
& $tool provision --service-name $ServiceName
if ($LASTEXITCODE -ne 0) {
    throw "hkdfguard-v1-initialize provision failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host "Service '$ServiceName' is provisioned. The native integration tests now run on this machine:"
Write-Host '    dotnet test test/HkdfGuard.KeyWrapping.V1.Test'
