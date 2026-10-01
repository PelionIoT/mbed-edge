# SPDX-License-Identifier: Apache-2.0
# Run from an elevated Windows PowerShell 5.1+ prompt. No downloads or passwords.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall')][string]$Action = 'Install',
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')][string]$ServiceName = 'EdgeCore',
    [string]$BinaryDirectory,
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'Izuma/EdgeCore'),
    [string]$DataDirectory = (Join-Path $env:ProgramData 'Izuma/EdgeCore'),
    [string]$ProvisioningFile,
    [ValidateRange(0,65535)][int]$HttpPort = 8080,
    [ValidateRange(1,65535)][int]$ProtocolPort = 7681,
    [ValidateSet('Automatic','Manual')][string]$StartupType = 'Automatic',
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'service-tools.ps1')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Service registration and ACL configuration require an elevated PowerShell prompt.'
}

function Invoke-ServiceControl {
    param([string[]]$Arguments)
    $output = Invoke-EdgeServiceControl -Arguments $Arguments
    $output | Write-Verbose
}
function Get-SafeDirectory {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'Directories must be absolute local drive paths.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($full.Length -le 3) { throw 'A drive root cannot be a service directory.' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Directory is a file or reparse point: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $full
}
function Set-ServiceDirectoryAcl {
    param([string]$Path, [Security.Principal.SecurityIdentifier]$ServiceSid,
          [Security.AccessControl.FileSystemRights]$Rights)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $propagate = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    # LocalService is shared by other services. OWNER RIGHTS suppresses the
    # implicit WRITE_DAC granted to owners of files created by that account.
    foreach ($entry in @(@('S-1-5-18','FullControl'), @('S-1-5-32-544','FullControl'),
            @($ServiceSid.Value,$Rights), @('S-1-3-4','ReadPermissions'))) {
        $sid = [Security.Principal.SecurityIdentifier]$entry[0]
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,
            [Security.AccessControl.FileSystemRights]$entry[1], $inherit, $propagate, $allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Quote-ServiceArgument {
    param([string]$Value)
    # All generated values are validated names, ports, or absolute file paths.
    if ($Value.Contains('"') -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw 'Invalid character in service command line.'
    }
    return '"' + $Value + '"'
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Action -eq 'Uninstall') {
    if ($existing) {
        $registered = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        if ($registered.PathName -notmatch ('--service-name\s+' + [regex]::Escape($ServiceName) + '(\s|$)') -or
            $registered.PathName -notmatch 'edge-core\.exe"?\s+--service\s') {
            throw 'Refusing to remove a service that was not configured as native Edge Core.'
        }
        if ($existing.Status -ne 'Stopped') {
            $existing.Stop()
            $existing.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        Invoke-ServiceControl -Arguments @('delete',$ServiceName)
    }
    Write-Output "Service removed. Binaries, provisioning, logs and persisted identity retained."
    return
}
if ($existing) { throw "Service $ServiceName already exists. Uninstall preserves identity; reinstall afterward." }
if (-not $BinaryDirectory) { throw 'Specify -BinaryDirectory containing edge-core.exe and its runtime DLLs.' }
$source = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$install = Get-SafeDirectory $InstallDirectory
$data = Get-SafeDirectory $DataDirectory
if ($install -eq $data -or $install.StartsWith($data + '\',[StringComparison]::OrdinalIgnoreCase) -or
    $data.StartsWith($install + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installation and data directories must be separate.'
}
if ($source -eq $install) { throw 'BinaryDirectory must differ from InstallDirectory.' }
# These directories belong exclusively to this service; never reuse shared trees.
if (Test-Path -LiteralPath $install) {
    if (Get-ChildItem -LiteralPath $install -Force | Select-Object -First 1) {
        throw 'InstallDirectory must be empty. Stage upgrades separately; never overwrite a live installation.'
    }
}
foreach ($required in @('edge-core.exe','event.dll','event_core.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $required) -PathType Leaf)) { throw "Missing $required" }
}
foreach ($pattern in @('libcrypto-3*.dll','libssl-3*.dll')) {
    if (-not (Get-ChildItem -LiteralPath $source -Filter $pattern -File)) { throw "Missing $pattern" }
}
$provision = $null
$jsonProvision = $null
$derFiles = @()
if ($ProvisioningFile) {
    $provision = (Resolve-Path -LiteralPath $ProvisioningFile).Path
    if ([IO.Path]::GetExtension($provision) -notin @('.cbor','.json')) { throw 'Provisioning must be a .cbor or .json file.' }
    if ([IO.Path]::GetExtension($provision) -eq '.json') {
        try { $jsonProvision = Get-Content -LiteralPath $provision -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { throw 'Cannot parse the provisioning JSON.' }
        if ($jsonProvision.SchemeVersion -ne '0.0.1') { throw 'Unsupported provisioning scheme version.' }
        $sourceFolder = [IO.Path]::GetDirectoryName($provision)
        foreach ($group in @('Certificates','Keys')) {
            $index = 0
            foreach ($entry in $jsonProvision.$group) {
                if ($entry.Data -isnot [string] -or -not $entry.Data -or $entry.Format -ne 'der') {
                    throw 'JSON certificate/key entries require a local DER file path.'
                }
                $reference = $entry.Data
                if ($reference -match '^[A-Za-z]:[\\/]') { $file = [IO.Path]::GetFullPath($reference) }
                elseif ($reference -match '[:]' -or $reference -match '^[\\/]') { throw 'DER paths must be local absolute paths or relative bundle paths.' }
                else { $file = [IO.Path]::GetFullPath((Join-Path $sourceFolder $reference)) }
                Get-SafeDirectory ([IO.Path]::GetDirectoryName($file)) | Out-Null
                $item = Get-Item -LiteralPath $file -Force
                if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -eq 0) {
                    throw 'DER source must be a nonempty regular file.'
                }
                $filename = "$group-$index.der"
                $derFiles += @{source=$file; filename=$filename}
                $entry.Data = $filename
                $index++
            }
        }
    }
}
$state = Get-SafeDirectory (Join-Path $data 'state')
$logs = Get-SafeDirectory (Join-Path $data 'logs')
$config = Get-SafeDirectory (Join-Path $data 'config')
$manifest = Join-Path $data 'service-install.json'
if (Test-Path -LiteralPath $manifest) {
    $retained = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ($retained.serviceName -ne $ServiceName) { throw 'DataDirectory belongs to another service identity.' }
}
# Avoid inherited/explicit permissive ACLs and links in retained identity trees.
if (Test-Path -LiteralPath $data) {
    foreach ($item in Get-ChildItem -LiteralPath $data -Force -Recurse) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point in service data: $($item.FullName)" }
    }
}
$created = $false
try {
    $exe = Join-Path $install 'edge-core.exe'
    $arguments = @((Quote-ServiceArgument $exe), '--service', '--service-name', $ServiceName,
        '--data-dir', (Quote-ServiceArgument $state), '--service-log', (Quote-ServiceArgument (Join-Path $logs 'edge-core.log')),
        '--bind', '127.0.0.1', '--http-port', "$HttpPort", '--edge-pt-address', "127.0.0.1:$ProtocolPort")
    if ($provision) {
        $extension = [IO.Path]::GetExtension($provision)
        $provisionTarget = Join-Path $config ('provisioning' + $extension)
        $option = '--cbor-conf'; if ($extension -eq '.json') { $option = '--json-conf' }
        $arguments += @($option,(Quote-ServiceArgument $provisionTarget))
    }
    # Demand start until all files and restrictions are in place.
    Invoke-ServiceControl -Arguments @('create',$ServiceName,'type=','own','start=','demand',
        'obj=','NT AUTHORITY\LocalService','binPath=',($arguments -join ' '),'DisplayName=',"Izuma Edge Core ($ServiceName)")
    $created = $true
    $account = New-Object Security.Principal.NTAccount('NT SERVICE',$ServiceName)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier])
    Invoke-ServiceControl -Arguments @('sidtype',$ServiceName,'restricted')
    Invoke-ServiceControl -Arguments @('privs',$ServiceName,'SeChangeNotifyPrivilege')
    # Allow the adapter's bounded 20-second cleanup before normal OS shutdown.
    # This changes only this service, never the machine-wide kill timeout.
    Set-EdgeServicePreshutdownTimeout -ServiceName $ServiceName -Milliseconds 25000
    # icacls /setowner removes OWNER RIGHTS entries. Set retained ownership
    # before applying the final DACLs, so those entries survive and inherit.
    foreach ($folder in @($config,$state,$logs)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $output = & "$env:SystemRoot/System32/icacls.exe" $folder /setowner '*S-1-5-32-544' /T /Q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Cannot secure retained ownership: $output" }
    }
    Set-ServiceDirectoryAcl $install $sid ReadAndExecute
    Set-ServiceDirectoryAcl $data $sid ReadAndExecute
    Set-ServiceDirectoryAcl $config $sid ReadAndExecute
    Set-ServiceDirectoryAcl $state $sid Modify
    Set-ServiceDirectoryAcl $logs $sid Modify
    @{serviceName=$ServiceName; installDirectory=$install; schemaVersion=1} |
        ConvertTo-Json | Set-Content -LiteralPath $manifest
    # Reset retained children to inherit the newly protected directory ACLs.
    foreach ($folder in @($config,$state,$logs)) {
        $output = & "$env:SystemRoot/System32/icacls.exe" (Join-Path $folder '*') /reset /T /Q 2>&1
        if ($LASTEXITCODE -ne 0 -and (Get-ChildItem -LiteralPath $folder -Force | Select-Object -First 1)) {
            throw "Cannot secure retained data: $output"
        }
    }
    Copy-Item -LiteralPath (Join-Path $source 'edge-core.exe') -Destination $install
    Get-ChildItem -LiteralPath $source -Filter '*.dll' -File | Copy-Item -Destination $install
    if ($jsonProvision) {
        foreach ($file in $derFiles) {
            Copy-Item -LiteralPath $file.source -Destination (Join-Path $config $file.filename)
        }
        # Self-contained UTF-8 bundle with references relative to this JSON.
        $utf8 = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($provisionTarget,($jsonProvision | ConvertTo-Json -Depth 30),$utf8)
    } elseif ($provision) { Copy-Item -LiteralPath $provision -Destination $provisionTarget }
    Invoke-ServiceControl -Arguments @('failure',$ServiceName,'reset=','86400','actions=','restart/5000/restart/30000/none/0')
    Invoke-ServiceControl -Arguments @('failureflag',$ServiceName,'1')
    Invoke-ServiceControl -Arguments @('description',$ServiceName,'Native Izuma Edge Core; restricted LocalService runtime; state retained on uninstall.')
    if ($StartupType -eq 'Automatic') { Invoke-ServiceControl -Arguments @('config',$ServiceName,'start=','delayed-auto') }
    if ($Start) {
        Start-Service -Name $ServiceName
        (Get-Service $ServiceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(40))
    }
    Write-Output "Installed $ServiceName as restricted LocalService. State: $state"
} catch {
    if ($created) { & "$env:SystemRoot/System32/sc.exe" delete $ServiceName | Out-Null }
    throw
}
