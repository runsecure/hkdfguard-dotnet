<#
.SYNOPSIS
    The complete signed package build on a developer machine: build and test
    Release, Authenticode-sign every assembly built from this repository
    through Azure Artifact Signing, pack, and verify the signatures inside
    every package. The local equivalent of the release workflow's build and
    sign jobs.

.DESCRIPTION
    1. Checks the Artifact Signing setup first (signtool, the Artifact Signing
       plugin, build\signing\metadata.json, `az account show`), so a
       misconfiguration fails before any build work.
    2. Removes earlier Release output, so nothing stale is signed or packed.
    3. Restores the locked dependency graph, builds Release with -Version
       stamped in, and runs the tests.
    4. Signs each project's assembly in bin\Release\<tfm>\ - the copy
       `dotnet pack` takes - and verifies it.
    5. Packs every project under src\ with --no-build into artifacts\packages.
    6. Opens every package and verifies every assembly in it is validly
       signed and timestamped, then prints each package's SHA-256.

    The packages themselves are not NuGet-signed; see README.md, "Signing and
    releases". Uses your own `az login`, which needs the Artifact Signing
    Certificate Profile Signer role. Needs no elevation. Stops at the first
    failure.

.PARAMETER Version
    The package version, e.g. 1.2.3 or 1.2.3-rc.1.

.PARAMETER SkipTests
    Build without running the tests.

.PARAMETER SigningMetadata
    Artifact Signing metadata JSON. Default: build\signing\metadata.json.

.PARAMETER SigningDlib
    Path to the x64 Azure.CodeSigning.Dlib.dll. Default: the Artifact Signing
    client tools' install location.

.EXAMPLE
    scripts\build-signed.bat -Version 0.1.0
    powershell -File scripts\Build-Signed.ps1 -Version 0.1.0 -SkipTests
#>
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$')]
    [string]$Version,
    [switch]$SkipTests,
    [string]$SigningMetadata,
    [string]$SigningDlib
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Write-Section($title) {
    Write-Host ""
    Write-Host "==== $title ====" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "[OK]   $msg" -ForegroundColor Green }

. (Join-Path $PSScriptRoot "ArtifactSigning.ps1")
. (Join-Path $PSScriptRoot "HkdfGuardPackaging.ps1")

# ---- 1. Signing preflight ---------------------------------------------------
Write-Section "Checking the Artifact Signing setup"
$signingConfig = Initialize-ArtifactSigning -MetadataPath $SigningMetadata -DlibPath $SigningDlib
Write-Ok "signing setup is ready"

# ---- 2. Clean earlier Release output ----------------------------------------
Write-Section "Removing earlier Release output"
foreach ($project in Get-HkdfGuardPackableProjects -RepoRoot $RepoRoot) {
    foreach ($dir in "bin\Release", "obj\Release") {
        $path = Join-Path $project.DirectoryName $dir
        if (Test-Path $path) { Remove-Item -Recurse -Force $path }
    }
}
Write-Ok "clean"

# ---- 3. Build and test ------------------------------------------------------
Write-Section "Building $Version"
Invoke-HkdfGuardBuild -RepoRoot $RepoRoot -Version $Version -SkipTests:$SkipTests
Write-Ok "built$(if (-not $SkipTests) { ' and tested' })"

# ---- 4. Sign the assemblies -------------------------------------------------
Write-Section "Signing the assemblies"
$assemblies = Get-HkdfGuardBuiltAssemblies -RepoRoot $RepoRoot
Invoke-ArtifactSigning -Files $assemblies -Config $signingConfig

# ---- 5. Pack ----------------------------------------------------------------
Write-Section "Packing"
$packageDir = Join-Path $RepoRoot "artifacts\packages"
$packages = Invoke-HkdfGuardPack -RepoRoot $RepoRoot -Version $Version -OutputDirectory $packageDir

# ---- 6. Verify the packages as shipped --------------------------------------
Write-Section "Verifying the assemblies inside every package"
Assert-HkdfGuardPackagesSigned -Packages $packages -Config $signingConfig

Write-Section "Done"
foreach ($file in Get-ChildItem $packageDir -File | Sort-Object Name) {
    $hash = (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLower()
    Write-Host ("{0}  {1}" -f $hash, $file.FullName.Substring($RepoRoot.Length + 1))
}
Write-Host ""
Write-Host "$($packages.Count) packages built; every assembly in them is signed and timestamped." -ForegroundColor Green
Write-Host "The packages themselves are not NuGet-signed." -ForegroundColor Yellow
