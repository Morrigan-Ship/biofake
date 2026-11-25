<#
.SYNOPSIS
    One-shot installation of the BioFake virtual fingerprint sensor package.

.DESCRIPTION
    Must run elevated (Administrator). Performs the manual steps documented in
    README.md:
      1. optionally enables driver test signing (bcdedit /set testsigning on)
      2. imports biofake-test.cer into LocalMachine\Root and TrustedPublisher
      3. delegates node creation (SWD\BioFake / SWD\BioFakeCtl), driver staging
         via pnputil, engine plug-in copy and WbioSrvc restart to
         "biofakectl.exe install"
      4. optionally verifies the WinBio unit with "biofakectl.exe test"

.PARAMETER PackageDir
    Directory containing the package files (default: the directory of this
    script, i.e. the extracted zip).

.PARAMETER EnableTestSigning
    Also run "bcdedit /set testsigning on" (requires a reboot to take effect).

.PARAMETER Test
    Run "biofakectl.exe test" at the end to enumerate WinBio units.

.EXAMPLE
    .\install.ps1 -EnableTestSigning -Test
#>
[CmdletBinding()]
param(
    [string]$PackageDir,
    [switch]$EnableTestSigning,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'install.ps1 must be run from an elevated PowerShell (Run as Administrator).'
}

if (-not $PackageDir) { $PackageDir = $PSScriptRoot }
$ctl = Join-Path $PackageDir 'biofakectl.exe'
$inf = Join-Path $PackageDir 'biofake_wudf.inf'
$cer = Join-Path $PackageDir 'biofake-test.cer'

foreach ($f in @($ctl, $inf)) {
    if (-not (Test-Path $f)) { throw "required file not found: $f" }
}

if ($EnableTestSigning) {
    Write-Host 'Enabling driver test signing (effective after reboot)...'
    & bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw 'bcdedit failed' }
}

if (Test-Path $cer) {
    Write-Host 'Importing test certificate into LocalMachine Root and TrustedPublisher...'
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
} else {
    Write-Warning 'biofake-test.cer not found; installation will only work if the package is properly signed.'
}

Write-Host 'Installing driver package and creating device nodes (biofakectl.exe install)...'
& $ctl install $inf
if ($LASTEXITCODE -ne 0) { throw "biofakectl install failed (exit $LASTEXITCODE)" }

if ($Test) {
    & $ctl test
    if ($LASTEXITCODE -ne 0) { throw "biofakectl test failed (exit $LASTEXITCODE)" }
}

Write-Host 'Done. Device Manager should now show "BioFake Virtual Fingerprint Sensor".'
