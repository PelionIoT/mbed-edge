# SPDX-License-Identifier: Apache-2.0
# Shared offline package validation; Windows PowerShell 5.1+.
function Assert-EdgeAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Use an elevated Windows PowerShell prompt.'
    }
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell for this x64 package.' }
}
function Get-EdgeLocalDirectory {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'Use absolute local drive directories.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($full.Length -le 3) { throw 'Do not use a drive root.' }
    for ($current=$full; $current; $current=[IO.Path]::GetDirectoryName($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'A package directory or ancestor is a file/reparse point.'
            }
        }
    }
    return $full
}
function Assert-EdgeNativeImage {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Missing DOS header.' }
        $stream.Position=0x3c; $header=$reader.ReadUInt32()
        if ($header -gt $stream.Length-264) { throw 'Invalid PE offset.' }
        $stream.Position=$header
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Expected x64 PE image.' }
        $optional=$header+24; $stream.Position=$optional
        if ($reader.ReadUInt16() -ne 0x20b) { throw 'Expected PE32+ image.' }
        $stream.Position=$optional+112+14*8
        if ($reader.ReadUInt32() -ne 0) { throw 'Managed CLR images cannot be packaged as native edge-core.' }
    } finally { $reader.Dispose(); $stream.Dispose() }
}
function Test-EdgePackage {
    param([string]$Directory,[switch]$AllowUnsigned,[string]$SignerThumbprint)
    $root = Get-EdgeLocalDirectory $Directory
    $manifest = Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or $manifest.product -ne 'Izuma Edge Core' -or
        $manifest.architecture -ne 'x64' -or $manifest.profile -ne 'BYOC/OpenSSL/Release' -or
        $manifest.version -notmatch '^\d+\.\d+\.\d+$' -or -not $manifest.files.Count) {
        throw 'Unsupported package manifest.'
    }
    [void][version]$manifest.version
    $names=@(); $expected=@('package.json','package.cat')
    foreach ($entry in $manifest.files) {
        if ($entry.path -notmatch '^(bin|scripts|licenses|prerequisites)/[A-Za-z0-9_.-]+$' -or
            $entry.path -in $names -or $entry.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
            throw 'Invalid or duplicate package member.'
        }
        $names += $entry.path; $expected += $entry.path
        $file=Get-Item -LiteralPath (Join-Path $root $entry.path) -Force
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $file.Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw 'Package member failed integrity validation.'
        }
    }
    foreach ($member in Get-ChildItem -LiteralPath $root -Force -Recurse) {
        if ($member.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in package.' }
        if (-not $member.PSIsContainer) {
            $relative=$member.FullName.Substring($root.Length+1).Replace('\','/')
            if ($relative -notin $expected) { throw 'Unexpected file in package.' }
        }
    }
    foreach ($required in @('bin/edge-core.exe','bin/event.dll','bin/event_core.dll',
            'scripts/install-service.ps1','scripts/service-tools.ps1','scripts/package-tools.ps1',
            'scripts/install-package.ps1','scripts/update-service.ps1','prerequisites/vc_redist.x64.exe')) {
        if ($required -notin $names) { throw "Missing package member: $required" }
    }
    foreach ($pattern in @('^bin/libcrypto-3[^/]*\.dll$','^bin/libssl-3[^/]*\.dll$')) {
        if (@($names | Where-Object {$_ -match $pattern}).Count -ne 1) { throw 'Expected one OpenSSL 3 TLS and crypto DLL.' }
    }
    Assert-EdgeNativeImage (Join-Path $root 'bin/edge-core.exe')
    $catalog=Join-Path $root 'package.cat'
    if ((Test-FileCatalog -Path $root -CatalogFilePath $catalog) -ne 'Valid') { throw 'Package catalog validation failed.' }
    $signature=Get-AuthenticodeSignature -LiteralPath $catalog
    if (-not $AllowUnsigned) {
        if ($SignerThumbprint -notmatch '^[a-fA-F0-9]{40}$' -or $signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Thumbprint -ne $SignerThumbprint) {
            throw 'A valid catalog signed by the configured release certificate is required. Use -AllowUnsigned only for qualification.'
        }
    }
    return $manifest
}
function Protect-EdgeRelease {
    param([string]$Directory,[string]$ServiceName)
    $account=New-Object Security.Principal.NTAccount('NT SERVICE',$ServiceName)
    $sid=$account.Translate([Security.Principal.SecurityIdentifier])
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@($sid.Value,'ReadAndExecute'))) {
        $rule=New-Object Security.AccessControl.FileSystemAccessRule(
            ([Security.Principal.SecurityIdentifier]$entry[0]),$entry[1],'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Directory -AclObject $acl
}
function Wait-EdgeServiceReady {
    param([string]$Name,[string]$Command,[int]$HttpPort,[int]$Seconds=40)
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $service=Get-CimInstance Win32_Service -Filter "Name='$Name'"
        if ($service.PathName -ne $Command) { throw 'Service command changed during activation.' }
        if ($service.State -eq 'Stopped') { throw "Candidate service stopped: $($service.ExitCode)/$($service.ServiceSpecificExitCode)." }
        if ($service.State -eq 'Running') {
            if ($HttpPort -eq 0) { return }
            try { [void](Invoke-RestMethod -Uri "http://127.0.0.1:$HttpPort/status" -TimeoutSec 2); return } catch { }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Local service readiness timed out.'
}
