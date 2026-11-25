<#
.SYNOPSIS
    Collects biofake build outputs, optionally test-signs them, and packs
    package\biofake-package.zip.

.DESCRIPTION
    Windows-only helper used both locally and by GitHub Actions.
    Collected files:
      BioFakeWudf.dll            UMDF 2.x WBDI virtual fingerprint driver
      biofake_wudf.inf           stamped INF
      biofake_wudf.cat           driver package catalog
      BioFakeEngineAdapter.dll   WinBio engine adapter plug-in
      biofakectl.exe             user-mode control tool
      biofake-test.cer           self-signed test certificate (with -Sign)

.PARAMETER Configuration
    Build configuration to collect (default Release).

.PARAMETER Platform
    Platform to collect (default x64).

.PARAMETER Sign
    Create a self-signed code-signing certificate and sign the catalog and
    binaries with it.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Platform = 'x64',
    [switch]$Sign
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Find-Output {
    param([Parameter(Mandatory)][string]$Name)
    $hit = Get-ChildItem -Path $repoRoot -Recurse -Filter $Name -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(packages|\.git|\.github|package)\\' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $hit) { throw "Build output '$Name' not found under $repoRoot" }
    return $hit.FullName
}

function Find-Signtool {
    $candidates = @()
    $pf86 = ${env:ProgramFiles(x86)}
    if ($pf86) {
        $kitsBin = Join-Path $pf86 'Windows Kits\10\bin'
        if (Test-Path $kitsBin) {
            $candidates += Get-ChildItem -Path $kitsBin -Recurse -Filter 'signtool.exe' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\(x64|x86)\\' }
        }
    }
    $packagesDir = Join-Path $repoRoot 'packages'
    if (Test-Path $packagesDir) {
        $candidates += Get-ChildItem -Path $packagesDir -Recurse -Filter 'signtool.exe' -File -ErrorAction SilentlyContinue
    }
    $best = $candidates | Sort-Object FullName -Descending | Select-Object -First 1
    if ($null -eq $best) { throw 'signtool.exe not found (install the Windows SDK or run nuget restore first)' }
    return $best.FullName
}

$names = @('BioFakeWudf.dll','biofake_wudf.inf','biofake_wudf.cat','BioFakeEngineAdapter.dll','biofakectl.exe')
$found = @{}
foreach ($n in $names) { $found[$n] = Find-Output -Name $n }

$packageDir = Join-Path $repoRoot 'package'
$stageDir = Join-Path $packageDir 'stage'
Remove-Item $packageDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stageDir | Out-Null

foreach ($kv in $found.GetEnumerator()) {
    Copy-Item -Path $kv.Value -Destination $stageDir -Force
    Write-Host ("packed {0,-26} <- {1}" -f $kv.Key, $kv.Value)
}
Copy-Item (Join-Path $repoRoot 'scripts\install.ps1') $stageDir -Force
Copy-Item (Join-Path $repoRoot 'README.md') $stageDir -Force

if ($Sign) {
    $signtool = Find-Signtool
    Write-Host "signtool: $signtool"

    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=BioFake Test,O=BioFake Project' `
        -KeyUsage DigitalSignature -KeyUsageProperty Sign -FriendlyName 'BioFake Test Signing' `
        -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(3)

    $pfxPath = Join-Path $env:TEMP 'biofake-test.pfx'
    $pw = ConvertTo-SecureString -String 'biofake' -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pw | Out-Null
    Export-Certificate -Cert $cert -FilePath (Join-Path $stageDir 'biofake-test.cer') | Out-Null

    foreach ($n in @('biofake_wudf.cat','BioFakeWudf.dll','BioFakeEngineAdapter.dll','biofakectl.exe')) {
        & $signtool sign /fd SHA256 /f $pfxPath /p biofake /t http://timestamp.digicert.com (Join-Path $stageDir $n)
        if ($LASTEXITCODE -ne 0) { throw "signtool failed for $n (exit $LASTEXITCODE)" }
    }
    Remove-Item $pfxPath -Force
    Write-Host 'Test-signed with a self-signed certificate (see biofake-test.cer in the package).'
}

$zipPath = Join-Path $packageDir 'biofake-package.zip'
Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -Force
Write-Host "package: $zipPath"
