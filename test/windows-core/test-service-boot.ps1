# SPDX-License-Identifier: Apache-2.0
# Elevated, offline setup for a real boot test. This script never reboots.
[CmdletBinding()]
param(
    [ValidateSet('Prepare','Verify','Cleanup')][string]$Action = 'Prepare',
    [string]$BuildDirectory,
    [string]$EvidenceDirectory,
    [string]$Manifest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# The protected observer snapshot keeps all three scripts in one directory.
$sharedTools = Join-Path $PSScriptRoot '../../windows/service-tools.ps1'
if (Test-Path -LiteralPath $sharedTools) { . $sharedTools }
else {
    . (Join-Path $PSScriptRoot 'service-tools.ps1')
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Boot-test preparation, observation and cleanup require elevation.'
}
$bootParent = Join-Path $env:ProgramData 'Izuma/EdgeCoreBootTests'

function Safe-Directory {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'Use an absolute local directory.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($full.Length -le 3) { throw 'Do not use a drive root.' }
    for ($current = $full; $current; $current = [IO.Path]::GetDirectoryName($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Unsafe directory: $current"
            }
        }
    }
    return $full
}
function Protect-ObserverDirectory {
    param([string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            ([Security.Principal.SecurityIdentifier]$sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Boot-Time { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
function Service-Info { param([string]$Name); Get-CimInstance Win32_Service -Filter "Name='$Name'" }
function Free-Port {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop(); return $port
}
function Assert-Configuration {
    param($Entry)
    $service = Service-Info $Entry.name
    if (-not $service -or $service.PathName -ne $Entry.command -or
        $service.StartName -ne 'NT AUTHORITY\LocalService' -or $service.StartMode -ne 'Auto') {
        throw "Service configuration changed: $($Entry.name)"
    }
    $config = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Entry.name)
    if ($config.DelayedAutoStart -ne 1 -or (Get-EdgeServicePreshutdownTimeout $Entry.name) -ne 25000) {
        throw "Delayed automatic startup / preshutdown configuration missing: $($Entry.name)"
    }
    return $service
}
function Wait-Connected {
    param($Entry)
    $deadline = [DateTime]::UtcNow.AddSeconds(150)
    do {
        if ((Service-Info $Entry.name).State -ne 'Running') { throw "Service exited: $($Entry.name)" }
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:$($Entry.httpPort)/status" -TimeoutSec 3
            if ($status.status -eq 'connected' -and $status.'internal-id') { return $status.'internal-id' }
        } catch { }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Cloud registration timed out: $($Entry.name)"
}
function Publish-Result {
    param($Value,$Plan)
    $json = $Value | ConvertTo-Json -Depth 6
    $json | Set-Content -LiteralPath (Join-Path $Plan.root 'results.json') -Encoding UTF8
    # Only a sanitized result is published to the workspace; the SYSTEM task
    # never executes code or reads a manifest from that writable directory.
    $json | Set-Content -LiteralPath (Join-Path $Plan.evidenceDirectory 'boot-results.json') -Encoding UTF8
}
function Remove-OwnedTest {
    param($Plan)
    $errors = @()
    foreach ($entry in $Plan.services) {
        try {
            if (Get-Service $entry.name -ErrorAction SilentlyContinue) {
                $service = Service-Info $entry.name
                if ($service.PathName -ne $entry.command) { throw 'Test service ImagePath changed; refusing removal.' }
                & (Join-Path $Plan.observer 'install-service.ps1') -Action Uninstall -ServiceName $entry.name | Out-Null
            }
        } catch { $errors += $_.Exception.Message }
    }
    try {
        $task = Get-ScheduledTask -TaskName $Plan.taskName -ErrorAction SilentlyContinue
        if ($task) {
            $expected = ConvertTo-EdgeNativeArguments @('-NoProfile','-ExecutionPolicy','Bypass','-File',
                (Join-Path $Plan.observer 'test-service-boot.ps1'),'-Action','Verify','-Manifest',(Join-Path $Plan.root 'manifest.json'))
            if ($task.Actions.Count -ne 1 -or $task.Actions[0].Arguments -ne $expected) {
                throw 'Observer task changed; refusing removal.'
            }
            Unregister-ScheduledTask -TaskName $Plan.taskName -Confirm:$false
        }
    } catch { $errors += $_.Exception.Message }
    if ($errors.Count) { throw ($errors -join ' ') }
}

if ($Action -eq 'Prepare') {
    if (-not $BuildDirectory -or -not $EvidenceDirectory) { throw 'Specify -BuildDirectory and a new -EvidenceDirectory.' }
    $build = (Resolve-Path -LiteralPath $BuildDirectory).Path
    $evidence = Safe-Directory $EvidenceDirectory
    if (Test-Path -LiteralPath $evidence) { throw 'EvidenceDirectory must be new.' }
    $parent = Safe-Directory $bootParent
    # A dedicated protected parent prevents an ordinary user replacing code
    # which the startup observer will execute as SYSTEM.
    Protect-ObserverDirectory $parent
    $tag = [Guid]::NewGuid().ToString('N')
    $root = Join-Path $parent $tag
    Protect-ObserverDirectory $root
    $observer = Join-Path $root 'observer'
    Protect-ObserverDirectory $observer
    $repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $observer 'test-service-boot.ps1')
    foreach ($file in @('install-service.ps1','service-tools.ps1')) {
        Copy-Item -LiteralPath (Join-Path $repo ('windows/' + $file)) -Destination $observer
    }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    $plan = [ordered]@{schema=1; root=$root; observer=$observer; evidenceDirectory=$evidence;
        taskName=('IzumaEdgeBoot_' + $tag); beforeBoot=(Boot-Time); services=@()}
    try {
        foreach ($configuration in @('Release','Debug')) {
            $entry = [ordered]@{configuration=$configuration; name=('IzumaEdgeBoot_' + $configuration + '_' + $tag);
                httpPort=(Free-Port); protocolPort=(Free-Port); install=(Join-Path $root "$configuration installation");
                data=(Join-Path $root "$configuration data"); command=''; identity=''; logOffset=0}
            & (Join-Path $observer 'install-service.ps1') -BinaryDirectory (Join-Path $build "bin/$configuration") `
                -ServiceName $entry.name -InstallDirectory $entry.install -DataDirectory $entry.data `
                -HttpPort $entry.httpPort -ProtocolPort $entry.protocolPort -StartupType Automatic
            $entry.command = (Service-Info $entry.name).PathName
            $plan.services += $entry
            Assert-Configuration $entry | Out-Null
            Start-Service $entry.name
            (Get-Service $entry.name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(40))
            $entry.identity = Wait-Connected $entry
            $entry.logOffset = (Get-Item -LiteralPath (Join-Path $entry.data 'logs/edge-core.log')).Length
        }
        $manifestPath = Join-Path $root 'manifest.json'
        $plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        $shell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $arguments = ConvertTo-EdgeNativeArguments @('-NoProfile','-ExecutionPolicy','Bypass','-File',
            (Join-Path $observer 'test-service-boot.ps1'),'-Action','Verify','-Manifest',$manifestPath)
        $taskAction = New-ScheduledTaskAction -Execute $shell -Argument $arguments -WorkingDirectory $observer
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
            -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $plan.taskName -Action $taskAction -Trigger $trigger -Principal $taskPrincipal -Settings $settings | Out-Null
        # Exercise the exact protected observer as SYSTEM without rebooting.
        # It detects the unchanged boot and records only a preflight result.
        Start-ScheduledTask -TaskName $plan.taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        $resultFile = Join-Path $root 'results.json'
        while (-not (Test-Path -LiteralPath $resultFile) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path -LiteralPath $resultFile)) { throw 'SYSTEM observer preflight did not report.' }
        $result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        if ($result.stage -ne 'awaiting-reboot' -or -not $result.observerIsSystem) { throw 'SYSTEM observer preflight failed.' }
        @{manifest=$manifestPath; taskName=$plan.taskName; services=@($plan.services.name)} |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'prepared.json') -Encoding UTF8
        Write-Output "Prepared. No reboot requested. Manifest: $manifestPath"
    } catch {
        $failure = $_
        try { Remove-OwnedTest $plan } catch { Write-Warning $_.Exception.Message }
        throw $failure
    }
    return
}

if (-not $Manifest) { throw 'Specify the protected -Manifest from Prepare.' }
$manifestPath = [IO.Path]::GetFullPath($Manifest)
$root = Safe-Directory ([IO.Path]::GetDirectoryName($manifestPath))
$tag = [IO.Path]::GetFileName($root)
if ($tag -notmatch '^[0-9a-f]{32}$' -or $root -ne (Join-Path (Safe-Directory $bootParent) $tag) -or
    [IO.Path]::GetFileName($manifestPath) -ne 'manifest.json') { throw 'Manifest is outside the owned boot-test namespace.' }
$plan = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($plan.schema -ne 1 -or $plan.root -ne $root -or $plan.observer -ne (Join-Path $root 'observer') -or
    $plan.taskName -ne ('IzumaEdgeBoot_' + $tag) -or $plan.services.Count -ne 2) { throw 'Invalid boot-test manifest.' }
foreach ($entry in $plan.services) {
    if ($entry.configuration -notin @('Release','Debug') -or
        $entry.name -ne ('IzumaEdgeBoot_' + $entry.configuration + '_' + $tag) -or
        $entry.install -ne (Join-Path $root "$($entry.configuration) installation") -or
        $entry.data -ne (Join-Path $root "$($entry.configuration) data")) { throw 'Invalid owned service in manifest.' }
}
if ($Action -eq 'Cleanup') {
    Remove-OwnedTest $plan
    Publish-Result @{stage='canceled'; passed=$false; cleanupVerified=$true; error=$null} $plan
    return
}
$currentBoot = Boot-Time
$isSystem = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18'
$result = [ordered]@{stage='verifying'; passed=$null; observerIsSystem=$isSystem;
    observerStartedUtc=[DateTime]::UtcNow.ToString('o'); beforeBoot=$plan.beforeBoot; afterBoot=$currentBoot;
    services=@(); cleanupVerified=$false; error=$null}
if ($currentBoot -eq $plan.beforeBoot) {
    try {
        if (-not $isSystem) { throw 'Observer preflight must run as SYSTEM.' }
        foreach ($entry in $plan.services) { Assert-Configuration $entry | Out-Null }
        $result.stage = 'awaiting-reboot'
    } catch { $result.stage='preflight-failed'; $result.error=$_.Exception.Message }
    Publish-Result $result $plan
    return
}
try {
    if (-not $isSystem) { throw 'Boot verification must run in the startup SYSTEM task.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(300)
    foreach ($entry in $plan.services) {
        # Delayed auto-start is observed; the observer never starts services.
        do {
            $service = Assert-Configuration $entry
            if ($service.State -eq 'Running') { break }
            Start-Sleep -Seconds 1
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($service.State -ne 'Running') { throw "Automatic startup timed out: $($entry.name)" }
        $process = Get-Process -Id $service.ProcessId
        if ($process.Path -ne (Join-Path $entry.install 'edge-core.exe')) { throw 'Unexpected service process.' }
        $stream = New-Object IO.FileStream((Join-Path $entry.data 'logs/edge-core.log'),
            [IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try {
            if ($stream.Length -lt $entry.logOffset) { throw 'Lifecycle log was truncated.' }
            [void]$stream.Seek($entry.logOffset,[IO.SeekOrigin]::Begin)
            $reader = New-Object IO.StreamReader($stream)
            try { $log = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $stop = [regex]::Match($log,'Service stop control=15; elapsed=(\d+) ms\.\r?\nService stopped with application exit code 0\.')
        if (-not $stop.Success -or [int64]$stop.Groups[1].Value -ge 20000 -or
            $log.IndexOf('Service starting with restricted LocalService identity.',$stop.Index + $stop.Length) -lt 0) {
            throw "Clean preshutdown followed by startup was not recorded: $($entry.name)"
        }
        $identity = Wait-Connected $entry
        if ($identity -ne $entry.identity) { throw "Cloud identity changed across reboot: $($entry.name)" }
        $result.services += @{configuration=$entry.configuration; name=$entry.name; automaticStart=$true;
            startupDelaySeconds=($process.StartTime.ToUniversalTime() - [DateTime]::Parse($currentBoot).ToUniversalTime()).TotalSeconds;
            preshutdownMilliseconds=[int64]$stop.Groups[1].Value; sameCloudIdentity=$true}
    }
    $result.passed = $true
} catch { $result.passed=$false; $result.error=$_.Exception.Message }
finally {
    try { Remove-OwnedTest $plan; $result.cleanupVerified=$true }
    catch { $result.passed=$false; $result.error += " Cleanup: $($_.Exception.Message)" }
    $result.stage = if ($result.passed) { 'passed' } else { 'failed' }
    Publish-Result $result $plan
}
if (-not $result.passed) { throw $result.error }
