# SPDX-License-Identifier: Apache-2.0
# Credential-free package validation. No admin, services or cloud required.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../windows/package-tools.ps1')
$source=(Resolve-Path -LiteralPath $PackageDirectory).Path
$out=Get-EdgeLocalDirectory ([IO.Path]::GetFullPath($OutputDirectory))
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new.' }
New-Item -ItemType Directory -Path $out | Out-Null
$result=[ordered]@{passed=$false; checks=@(); error=$null}
function Copy-Case {
    param([string]$Name)
    $directory=Join-Path $out $Name
    Copy-Item -LiteralPath $source -Destination $directory -Recurse
    return $directory
}
function Assert-Rejected {
    param([string]$Directory,[string]$Check)
    $rejected=$false
    try { [void](Test-EdgePackage $Directory -AllowUnsigned) } catch { $rejected=$true }
    if (-not $rejected) { throw "Invalid package accepted: $Check" }
    $result.checks += $Check
}
try {
    [void](Test-EdgePackage $source -AllowUnsigned)
    $result.checks += 'Intact x64 native BYOC/OpenSSL Release bundle accepted for qualification'
    $rejected=$false
    try { [void](Test-EdgePackage $source) } catch { $rejected=$_.Exception.Message -like 'A valid catalog signed*' }
    if (-not $rejected) { throw 'Unsigned deployment did not fail closed.' }
    $result.checks += 'Unsigned bundle rejected by production signature policy'
    $directory=Copy-Case 'modified-dll'
    $file=Join-Path $directory 'bin/event.dll'
    $bytes=[IO.File]::ReadAllBytes($file); $bytes[$bytes.Length-1]=$bytes[$bytes.Length-1] -bxor 1
    [IO.File]::WriteAllBytes($file,$bytes)
    Assert-Rejected $directory 'Modified runtime DLL rejected'
    $directory=Copy-Case 'unexpected-file'
    'Unexpected package content' | Set-Content -LiteralPath (Join-Path $directory 'bin/extra.dll')
    Assert-Rejected $directory 'Extra unlisted file rejected'
    $directory=Copy-Case 'path-traversal'
    $manifestPath=Join-Path $directory 'package.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.files[0].path='../outside.exe'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Assert-Rejected $directory 'Manifest path traversal rejected'
    $directory=Copy-Case 'manifest-tamper'
    $manifestPath=Join-Path $directory 'package.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.version='0.21.9999'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Assert-Rejected $directory 'Catalog rejects modified package version metadata'
    $directory=Copy-Case 'wrong-profile'
    $manifestPath=Join-Path $directory 'package.json'
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.profile='Developer/Debug'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Assert-Rejected $directory 'Developer/Debug package rejected'
    $result.passed=$true
} catch { $result.error=$_.Exception.Message }
finally { $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $out 'results.json') }
if (-not $result.passed) { throw $result.error }
$result.checks | Write-Output
