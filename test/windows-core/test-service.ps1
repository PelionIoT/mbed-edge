# SPDX-License-Identifier: Apache-2.0
# Run elevated. Creates only uniquely named test services; keeps evidence/data.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BinaryDirectory,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$RealCloud,
    [switch]$OfflineStartup,
    [string]$ProvisioningFile
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$installer = Join-Path $repo 'windows/install-service.ps1'
. (Join-Path $repo 'windows/service-tools.ps1')
$binary = (Resolve-Path -LiteralPath $BinaryDirectory).Path
if ($OfflineStartup -and -not $RealCloud) { throw '-OfflineStartup requires -RealCloud.' }
if ($ProvisioningFile -and -not $RealCloud) { throw '-ProvisioningFile requires -RealCloud and a BYOC binary.' }
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'OutputDirectory must be new; previous test identities are retained.' }
New-Item -ItemType Directory -Path $out | Out-Null
$suffix = [Guid]::NewGuid().ToString('N').Substring(0,12)
$probeName = 'IzumaEdgeProbe_' + $suffix
$edgeName = 'IzumaEdgeCloud_' + $suffix
$results = [ordered]@{passed=$false; checks=@(); outputDirectory=$out; cloudIdentity=$null; error=$null}
function Record {
    param([string]$Check)
    $results.checks += $Check
    ('{0:o} {1}' -f [DateTime]::UtcNow,$Check) | Add-Content -LiteralPath (Join-Path $out 'progress.log')
}
function Invoke-TestSc {
    param([string[]]$Arguments)
    return (Invoke-EdgeServiceControl -Arguments $Arguments)
}
function ServiceInfo { param([string]$Name); Get-CimInstance Win32_Service -Filter "Name='$Name'" }
function Wait-State {
    param([string]$Name,[string]$State,[int]$Seconds=40)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $info = ServiceInfo $Name
        if ($info.State -eq $State) { return $info }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Name did not become $State; current state: $($info.State), exit: $($info.ExitCode)"
}
function Start-TestService {
    param([string]$Name)
    try { Start-Service $Name } catch {
        $failure = ServiceInfo $Name
        throw "$Name failed to start: Win32=$($failure.ExitCode), service=$($failure.ServiceSpecificExitCode). $($_.Exception.Message)"
    }
    return (Wait-State $Name 'Running')
}
function Stop-TestService {
    param([string]$Name)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Stop-Service $Name
    $info = Wait-State $Name 'Stopped' 30
    if ($info.ExitCode -ne 0 -or $timer.Elapsed.TotalSeconds -ge 20) {
        throw "Service did not stop cleanly: $($info.ExitCode), $($timer.Elapsed.TotalSeconds)s"
    }
    return $info
}
function Write-Canary {
    param([string]$Path)
    'ACL test canary; must remain unchanged.' | Set-Content -LiteralPath $Path
}
function Assert-StateLocked {
    param([string]$StateDirectory,[string]$Mode)
    $arguments = @('--http-port','0')
    if ($Mode -eq 'explicit') { $arguments += @('--data-dir',$StateDirectory) }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $binary 'edge-core.exe'
    $info.Arguments = ConvertTo-EdgeNativeArguments -Arguments $arguments
    $info.WorkingDirectory = $StateDirectory
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $child = New-Object Diagnostics.Process
    $child.StartInfo = $info
    try {
        [void]$child.Start()
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(10000)) { $child.Kill(); throw 'Concurrent process failed to exit promptly.' }
        $output = $stdout.GetAwaiter().GetResult(); $errors = $stderr.GetAwaiter().GetResult()
        $output | Set-Content -LiteralPath (Join-Path $out "lock-$Mode.stdout.log")
        $errors | Set-Content -LiteralPath (Join-Path $out "lock-$Mode.stderr.log")
        if ($child.ExitCode -ne 1 -or $errors -notmatch 'Windows error 32') {
            throw "Shared identity directory was not locked: exit=$($child.ExitCode), stderr=$errors"
        }
    } finally { $child.Dispose() }
}
function Assert-Probe {
    param([string]$Path)
    $value = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if (-not $value.stateWrite -or $value.binWriteError -ne 5 -or $value.configReadError -ne 0 -or
        $value.configWriteError -ne 5 -or $value.foreignReadError -ne 5) { throw 'Restricted-token ACL probes failed.' }
    return $value
}
function Wait-Cloud {
    param([int]$Port,[string]$Name,[string]$ExpectedIdentity)
    $deadline = [DateTime]::UtcNow.AddSeconds(150)
    do {
        if ((ServiceInfo $Name).State -ne 'Running') { throw 'Cloud service exited.' }
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/status" -TimeoutSec 3
            if ($status.status -eq 'connected') {
                if ($ExpectedIdentity -and $status.'internal-id' -ne $ExpectedIdentity) { throw 'Cloud identity changed.' }
                return $status
            }
        } catch { if ($_.Exception.Message -eq 'Cloud identity changed.') { throw } }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Cloud did not register within 150 seconds.'
}
function Get-FreePort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop(); return $port
}
try {
    $stage = Join-Path $out 'probe-source'
    New-Item -ItemType Directory -Path $stage | Out-Null
    Get-ChildItem -LiteralPath $binary -Filter '*.dll' -File | Copy-Item -Destination $stage
    Copy-Item -LiteralPath (Join-Path $binary 'windows-service-probe.exe') -Destination (Join-Path $stage 'edge-core.exe')
    $probeInstall = Join-Path $out 'probe installation'
    $probeData = Join-Path $out 'probe data'
    & $installer -BinaryDirectory $stage -ServiceName $probeName -InstallDirectory $probeInstall -DataDirectory $probeData -StartupType Manual
    if ((Get-EdgeServicePreshutdownTimeout $probeName) -ne 25000) { throw 'Preshutdown timeout was not configured.' }
    Record 'Per-service preshutdown timeout configured to 25 seconds'
    Write-Canary (Join-Path $probeInstall 'acl-canary.txt')
    Write-Canary (Join-Path $probeData 'config/acl-canary.txt')
    $foreign = Join-Path $probeData 'foreign'
    New-Item -ItemType Directory -Path $foreign | Out-Null
    # Inherits only read access for this service; remove it completely here.
    $acl = Get-Acl -LiteralPath $foreign
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            ([Security.Principal.SecurityIdentifier]$sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $foreign -AclObject $acl
    Write-Canary (Join-Path $foreign 'acl-canary.txt')
    $originalCommand = (ServiceInfo $probeName).PathName
    $first = Start-TestService $probeName
    if ($first.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Wrong runtime identity.' }
    $probeResult = Join-Path $probeData 'state/probe.json'
    $identity = (Assert-Probe $probeResult).identity
    $ownerRule = (Get-Acl -LiteralPath $probeResult).GetAccessRules($true,$true,
        [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-3-4' }
    if (-not $ownerRule -or ($ownerRule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ChangePermissions)) {
        throw 'Service-created files lack the owner-rights ACL protection.'
    }
    Record 'Restricted LocalService/SID/privileges and state/config/binary/foreign ACL checks passed'
    # An administrator still cannot use the same identity directory concurrently.
    foreach ($mode in @('explicit','working-directory')) {
        Assert-StateLocked (Join-Path $probeData 'state') $mode
    }
    Record 'Concurrent identity-directory access rejected'
    Stop-TestService $probeName | Out-Null
    Start-TestService $probeName | Out-Null
    if ((Assert-Probe $probeResult).identity -ne $identity) { throw 'Restart lost probe identity.' }
    Record 'SCM graceful stop/start and persisted state passed'
    $beforeCrash = ServiceInfo $probeName
    $process = Get-Process -Id $beforeCrash.ProcessId
    if ($process.Path -ne (Join-Path $probeInstall 'edge-core.exe')) { throw 'Crash target is not the owned test process.' }
    Stop-Process -Id $process.Id -Force
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do { Start-Sleep -Milliseconds 200; $recovered = ServiceInfo $probeName } while (
        ($recovered.State -ne 'Running' -or $recovered.ProcessId -eq $beforeCrash.ProcessId) -and [DateTime]::UtcNow -lt $deadline)
    if ($recovered.State -ne 'Running' -or $recovered.ProcessId -eq $beforeCrash.ProcessId -or
        (Assert-Probe $probeResult).identity -ne $identity) { throw 'SCM crash recovery failed.' }
    Record 'SCM crash recovery restarted the process without losing state'
    Stop-TestService $probeName | Out-Null
    Invoke-TestSc -Arguments @('failure',$probeName,'reset=','0','actions=','none/0') | Out-Null
    Invoke-TestSc -Arguments @('config',$probeName,'obj=','LocalSystem') | Out-Null
    try { Start-Service $probeName } catch { }
    $denied = Wait-State $probeName 'Stopped'
    if ($denied.ExitCode -ne 5) { throw "Elevated identity was not rejected: $($denied.ExitCode)" }
    Invoke-TestSc -Arguments @('config',$probeName,'obj=','NT AUTHORITY\LocalService') | Out-Null
    Record 'Misconfigured LocalSystem identity rejected with access denied'
    Invoke-TestSc -Arguments @('config',$probeName,'binPath=',($originalCommand + ' --probe-fail-start')) | Out-Null
    try { Start-Service $probeName } catch { }
    $failed = Wait-State $probeName 'Stopped'
    if ($failed.ExitCode -ne 1066 -or $failed.ServiceSpecificExitCode -ne 42) { throw 'Startup failure exit status was not propagated.' }
    Record 'Startup failure propagated as service-specific exit code 42'
    Invoke-TestSc -Arguments @('config',$probeName,'binPath=',($originalCommand + ' --probe-hang-stop')) | Out-Null
    Start-TestService $probeName | Out-Null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Invoke-TestSc -Arguments @('stop',$probeName) | Out-Null
    $timedOut = Wait-State $probeName 'Stopped' 30
    # ERROR_TIMEOUT is 1460; WAIT_TIMEOUT (258) is a wait API return value.
    if ($timedOut.ExitCode -ne 1066 -or $timedOut.ServiceSpecificExitCode -ne 1460 -or
        $timer.Elapsed.TotalSeconds -gt 25) {
        throw "Hung service stop was not bounded/reported: Win32=$($timedOut.ExitCode), service=$($timedOut.ServiceSpecificExitCode), elapsed=$($timer.Elapsed.TotalSeconds)s"
    }
    Record 'Hung shutdown bounded at 20 seconds with ERROR_TIMEOUT (1460)'
    & $installer -Action Uninstall -ServiceName $probeName
    if (-not (Test-Path (Join-Path $probeData 'state/probe-identity.txt'))) { throw 'Uninstall removed identity.' }
    Record 'Uninstall retained identity and logs'
    if ($RealCloud) {
        $edgeInstall = Join-Path $out 'cloud installation'
        $edgeData = Join-Path $out 'cloud data'
        $http = Get-FreePort; $pt = Get-FreePort
        $provisionArguments = @{}
        if ($ProvisioningFile) { $provisionArguments.ProvisioningFile = $ProvisioningFile }
        & $installer -BinaryDirectory $binary -ServiceName $edgeName -InstallDirectory $edgeInstall -DataDirectory $edgeData -StartupType Manual -HttpPort $http -ProtocolPort $pt @provisionArguments
        Start-TestService $edgeName | Out-Null
        $cloud = Wait-Cloud $http $edgeName
        if (-not $cloud.'internal-id') { throw 'Registered cloud identity missing.' }
        $results.cloudIdentity = $cloud.'internal-id'
        Record 'Real edge-core registered with cloud under restricted LocalService'
        if ($ProvisioningFile) {
            $extension = [IO.Path]::GetExtension($ProvisioningFile)
            $installedProvision = Join-Path $edgeData ('config/provisioning' + $extension)
            $withheldProvision = $installedProvision + '.test-withheld'
            Move-Item -LiteralPath $installedProvision -Destination $withheldProvision
            Record 'Initial runtime provisioning accepted; installed input withheld to verify persisted credentials on restart'
        }
        if ($OfflineStartup) {
            $networkOut = Join-Path $out 'offline-startup'
            New-Item -ItemType Directory -Path $networkOut | Out-Null
            $targets = Join-Path $networkOut 'targets.json'
            $owned = ServiceInfo $edgeName
            @(@{processId=$owned.ProcessId; executable=(Join-Path $edgeInstall 'edge-core.exe')}) |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $targets
            $networkArguments = ConvertTo-EdgeNativeArguments @('-NoProfile','-ExecutionPolicy','Bypass','-File',
                (Join-Path $PSScriptRoot 'test-network-outage.ps1'),'-Targets',$targets,
                '-ResultsDirectory',$networkOut,'-DurationSeconds','60')
            $outage = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') `
                -ArgumentList $networkArguments -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput (Join-Path $networkOut 'helper.stdout.log') `
                -RedirectStandardError (Join-Path $networkOut 'helper.stderr.log')
            try {
                $deadline = [DateTime]::UtcNow.AddSeconds(20)
                do {
                    Start-Sleep -Milliseconds 250
                    $statusFile = Join-Path $networkOut 'outage-status.json'
                    $network = if (Test-Path -LiteralPath $statusFile) {
                        try { Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json } catch { $null }
                    }
                    if ($network.error) { throw $network.error }
                } while ($network.stage -ne 'blocked' -and [DateTime]::UtcNow -lt $deadline)
                if ($network.stage -ne 'blocked') { throw 'Offline-startup firewall block did not become active.' }
                Stop-TestService $edgeName | Out-Null
                $timer = [Diagnostics.Stopwatch]::StartNew()
                Start-TestService $edgeName | Out-Null
                if ($timer.Elapsed.TotalSeconds -ge 20) { throw 'SCM readiness waited for cloud connectivity.' }
                $local = Invoke-RestMethod -Uri "http://127.0.0.1:$http/status" -TimeoutSec 3
                if ($local.status -eq 'connected') { throw 'Offline-startup client was unexpectedly connected.' }
                Stop-TestService $edgeName | Out-Null
                Record 'Real service starts locally and stops cleanly while outbound cloud traffic is blocked'
            } finally {
                # The helper also has an independent bounded cleanup watchdog.
                if (-not $outage.WaitForExit(90000)) { throw 'Firewall helper did not finish; inspect its cleanup manifest.' }
                $network = Get-Content -LiteralPath (Join-Path $networkOut 'outage-status.json') -Raw | ConvertFrom-Json
                if (-not $network.cleanupVerified -or $network.error) { throw 'Offline-startup firewall cleanup failed.' }
            }
        }
        if ((ServiceInfo $edgeName).State -ne 'Stopped') { Stop-TestService $edgeName | Out-Null }
        Start-TestService $edgeName | Out-Null
        Wait-Cloud $http $edgeName $cloud.'internal-id' | Out-Null
        Stop-TestService $edgeName | Out-Null
        Record 'Real cloud service stopped cleanly and reconnected with the same persisted identity'
    }
    $results.passed = $true
} catch {
    $results.error = $_.Exception.Message
    $_ | Out-String | Set-Content (Join-Path $out 'failure.log')
    if ($probeData -and (Test-Path -LiteralPath (Join-Path $probeData 'state/probe.json'))) {
        $aclEvidence = foreach ($relative in @('state','state/probe.json')) {
            $security = Get-Acl -LiteralPath (Join-Path $probeData $relative)
            @{path=$relative; owner=$security.Owner; sddl=$security.Sddl}
        }
        $aclEvidence | ConvertTo-Json | Set-Content (Join-Path $out 'acl-evidence.json')
    }
} finally {
    foreach ($name in @($probeName,$edgeName)) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            try { & $installer -Action Uninstall -ServiceName $name } catch { $results.passed=$false; $results.error += " Cleanup: $($_.Exception.Message)" }
        }
    }
    foreach ($folder in @('probe data','cloud data')) {
        $log = Join-Path $out ($folder + '/logs/edge-core.log')
        if (Test-Path -LiteralPath $log) { Copy-Item -LiteralPath $log -Destination (Join-Path $out ($folder.Replace(' ','-') + '.log')) }
    }
    if ($withheldProvision -and (Test-Path -LiteralPath $withheldProvision)) {
        Move-Item -LiteralPath $withheldProvision -Destination $installedProvision
    }
    $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'results.json')
}
if (-not $results.passed) { throw $results.error }
