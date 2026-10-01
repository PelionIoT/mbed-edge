# Basic cloud connectivity test: Windows 10 and OpenSSL

Prepared: 2026-09-30. Updated: 2026-10-01. Status: **G0 and C1-C6 passed in Debug and Release on Windows 10 Pro x64**.

## Goal and current readiness

Connect a native Win32 x64 `edge-core.exe` on Windows 10 Pro to the actual Izuma
Cloud using a developer certificate downloaded from the selected cloud account.
Prove bootstrap, authenticated CoAP over TCP/TLS, registration, a live resource
read, identity persistence and recovery after a temporary connection loss.

Baseline branch: `experiment/win10support` in both repositories. At preparation,
Edge is at `e563ad6` and cloud-client is at `2deac3b`. Windows selects the shared
upstream OpenSSL TLS/crypto implementations and Windows PAL adapters.

The native console application now builds in Debug and Release with OpenSSL
3.5.9. Five PAL/common tests and four application smoke tests pass, including
fresh BYOC startup without a crash. The developer profile also builds, loads
the actual developer credentials into KCM and runs its application smoke tests.
An additional scheduler/PAL timer regression covers every client timer type.
Actual cloud bootstrap, registration, a fresh resource read and a clean restart
with the same identity have passed in Debug and Release. Each configuration
used its own baseline identity directory. Connection-loss recovery and the
15-minute stability check after recovery have passed in both configurations.
Both test clients stopped cleanly afterward, and the temporary firewall rules
were removed. These results cover the native console developer profile on
this Windows 10 host; service/installer and other Windows editions remain
separate milestones.

The longer Release run exposed scheduler clock drift: a configured 45-minute
registration update arrived after about 79 minutes, received `NOT_FOUND`, and
triggered a new registration under the same Device ID. A Windows-only fix now
advances the event clock using elapsed monotonic PAL ticks instead of counting
potentially coalesced callbacks. A five-second registration timer with a
1.5-second callback stall reproduced the defect at 8.55 seconds, then passed at
5.01 seconds in Debug and 5.00 seconds in Release. All four application tests
pass in each configuration. Both rebuilt clients subsequently renewed at the
intended 45-minute interval with `ACK CHANGED`, then passed fresh cloud reads.
The extended registration-renewal check has passed on this Windows 10 host.

This first milestone runs as a console process under a normal Windows user.
Windows service lifecycle, Intune/SCCM installation, firmware updates, host
reboot, translators and the other supported Windows editions have separate
follow-up tests. The same console procedure can later run from PowerShell on
Server Core, with the cloud portal operated from another computer.

## Developer provisioning route

Use the documented download of `mbed_cloud_dev_credentials.c`, then the existing
Edge **`DEVELOPER_MODE`** and `fcc_developer_flow()` to populate KCM. This uses
the shared OpenSSL backend; provisioning mode does not select the TLS library.
[Izuma's developer certificate steps](https://developer.izumanetworks.com/docs/device-management/current/connecting/linux-on-pc.html)
and [Edge's developer prerequisites](https://developer.izumanetworks.com/docs/device-management-edge/2.6/quick-start/lmp-quick-start.html)
describe the cloud-side workflow. Their Linux/Yocto build commands are replaced
by the native Windows commands below.

For this milestone, compile the downloaded C credential file into the test
binary. Keep existing runtime CBOR/JSON provisioning available for subsequent
tests; this plan does not replace it. Disable firmware updates and file-based
RoT. No update signing certificate or manifest tool is required for this build.
File-based RoT must remain off because this developer flow does not provision
`RoTFilePath`.

The download contains private key material as well as certificates and cloud
configuration. Keep it, the resulting binary/PDBs and credential storage in a
restricted test directory. Do not commit them or paste their contents into
logs or chat. Use a dedicated developer certificate for this test and do not
run simultaneous clients with the same persisted identity.

## Information to fill in before execution

| Item | Test value |
| --- | --- |
| Operator / run date | Pending |
| Portal URL and account name/ID | Pending; documentation links to `https://portal.mbedcloud.com/` |
| Region / cloud environment | Pending; confirm with the account owner |
| Certificate label / ID / expiry | Suggested label: `edge-win10-connectivity`; record the actual values |
| Bootstrap hostname and TCP port | From the downloaded configuration and effective client configuration |
| LwM2M hostname and TCP port | From the bootstrap result / runtime endpoint information |
| Windows edition, version and OS build | Windows 10 Pro x64; record the exact build |
| Edge / cloud-client revisions | Record the revisions actually tested, including any porting fixes |
| MSVC / Windows SDK / OpenSSL version | Record versions and OpenSSL DLL locations |
| Endpoint name / cloud Device ID | Populate after first registration; preserve for later cases |

User assistance is needed to sign in to the intended portal/account, complete
MFA if required, and download the developer credential file. Public
documentation is sufficient to prepare this plan; login is needed when we
execute it. A scoped API access key may also be needed if the portal cannot
issue a fresh resource read. Passwords and API keys stay out of this document.

## Gate G0: make the actual client runnable

Before declaring any cloud test executable:

1. **Completed for the console profile:** resolve the application build blockers recorded in
   [the Windows build notes](docs/windows-build.md): GNU-only declarations,
   POSIX thread/time/file/socket calls, event-loop integration and the bundled
   libwebsockets Windows build issues. Use Windows guards/files and existing
   PAL/HAL contracts for the required changes.
2. **Native transport smoke test passed:** Edge uses loopback TCP instead of
   a Unix domain socket. Its local
   listener must use a working native Windows transport. Keep any TCP listener
   on loopback for this test; cloud registration needs only outbound traffic.
   Windows uses `--edge-pt-address 127.0.0.1:7681`. The transport has no local
   user authentication yet; use an isolated test machine.
3. Build the developer profile below and verify `edge-core.exe --help` and
   `--version` run. Record native x64 output and its DLL dependencies; the
   runtime must not depend on WSL, Cygwin or an emulated Linux process.
4. Re-run `build-windows.ps1 -PalTests` in Debug and Release with the selected
   OpenSSL SDK after the porting changes. All five tests must pass. Verify the
   application uses the same shared OpenSSL sources and SDK.
5. Confirm KCM/ESFS/SOTP storage, Windows system entropy, DNS and PAL networking
   initialize in the real application. The previous crypto tests covered only
   selected algorithms; actual bootstrap must also exercise the credential,
   key and certificate operations it requires.

Gate result on 2026-10-01: **console build and local smoke checks passed;
developer credentials/provisioning pending**. Fresh unprovisioned BYOC startup
reaches the normal `Device not configured` exit. The developer profile must
still prove its credential-dependent storage, crypto and networking paths in
the actual executable before the cloud cases can pass.

## Preparation and build

### 1. Download the developer credential

In the selected portal, choose **Device identity > Certificates**, then
**New certificate > Create a developer certificate**. Give it the agreed test
label, confirm its active status, and choose **Download developer C file**.
Save the resulting `mbed_cloud_dev_credentials.c` to the credential directory
prepared below. If UI labels differ, use the equivalent developer-certificate
download, rather than a public CA certificate export.

Record certificate metadata and confirm it belongs to the intended account.
Use the downloaded account/URI configuration; do not substitute sample account
IDs or server settings from documentation.

### 2. Prepare isolated directories

Run from the Edge repository root. These are execution instructions, not
commands already run during preparation of this plan.

```powershell
$repo = (Get-Location).Path
$testRoot = Join-Path $repo 'build/windows-cloud-connectivity'
$credentialsDir = Join-Path $testRoot 'credentials'
$appBuild = Join-Path $testRoot 'build-dev'
$runDir = Join-Path $testRoot ('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $credentialsDir, $runDir | Out-Null
$credentialFile = Join-Path $credentialsDir 'mbed_cloud_dev_credentials.c'

# Download/copy the portal file to $credentialFile before continuing.
if (-not (Test-Path -LiteralPath $credentialFile)) {
    throw "Developer credential download is missing: $credentialFile"
}
Get-FileHash -LiteralPath $credentialFile -Algorithm SHA256
git check-ignore $credentialFile
git rev-parse HEAD
git -C lib/mbed-cloud-client rev-parse HEAD
```

The `build` directory is already ignored by Git. Use directory ACLs appropriate
to the test user. Each fresh baseline gets its own `$runDir`; stop/restart tests
reuse that same directory. Default PAL storage is `./mcc_config`, so the process
working directory determines which identity storage is used.

### 3. Build the developer profile with OpenSSL

```powershell
$openssl = 'D:/work/mbed-edge/build/deps/openssl-install'
# Replace this SDK path if a different native x64 OpenSSL 3.x SDK is used.
$credentialForCMake = $credentialFile.Replace('\', '/')
$devArguments = @(
    '-DBYOC_MODE=OFF',
    '-DDEVELOPER_MODE=ON',
    '-DROT_FROM_FILE=OFF',
    '-DMBED_CLOUD_CLIENT_USE_OPENSSL=ON',
    '-DTRACE_LEVEL=DEBUG',
    "-DMBED_CLOUD_IDENTITY_CERT_FILE=$credentialForCMake",
    '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
)
.\build-windows.ps1 -BuildDirectory $appBuild -Configuration Debug `
    -OpenSSLRoot $openssl -CMakeArgument $devArguments
```

Alternatively, the Windows developer helper validates the downloaded C file,
selects this profile and runs the CLI/transport smoke tests:

```powershell
.\test\windows-core\build-developer.ps1 -CredentialFile $credentialFile `
    -BuildDirectory $appBuild -OpenSSLRoot $openssl -Configuration Debug
```

The helper's default is BYOC; the trailing arguments deliberately override it.
Confirm the configure output selects developer provisioning, Windows and
OpenSSL, with firmware updates/FOTA disabled. Check that `ROT_FROM_FILE` is
off and the credential source is the downloaded file. Do not use `--cbor-conf`
or `--json-conf` with this developer-mode binary.

Expected Visual Studio output location is
`$appBuild/bin/Debug/edge-core.exe`, based on the current CMake output setting.
Verify the actual generated location. An absent executable or failed build is
a G0 failure, not a cloud/network failure.

### 4. Check the direct outbound path

Check Windows time and DNS, then TCP reachability to the effective bootstrap
endpoint. Once bootstrap supplies the LwM2M endpoint, check that host too.

```powershell
Get-Date
w32tm /query /status
$bootstrapHost = '<hostname from the effective bootstrap URI>'
$bootstrapPort = 5684 # Replace if the effective configuration specifies another port.
Resolve-DnsName $bootstrapHost
Test-NetConnection -ComputerName $bootstrapHost -Port $bootstrapPort
```

The repository's cloud-client configuration selects TCP. Izuma documents port
5684 for device traffic and TCP support; some Edge configurations use 443.
Use the actual endpoint/port, rather than assuming HTTPS access proves the
device path. Allow DNS and direct, unmodified outbound TLS to bootstrap and
the supplied LwM2M endpoint. TLS inspection/proxies are outside this milestone.
Do not disable server certificate verification to work around a failure.
[Network configuration](https://developer.izumanetworks.com/docs/device-management/current/connecting/connectivity-reqs.html)

## Execution cases and pass criteria

The time limits below are proposed test limits, not Izuma service guarantees.
Record elapsed time and the exact failure stage when a limit is exceeded.

### C1: first bootstrap and registration

Start from the new, empty `$runDir`. With G0 satisfied:

```powershell
$edgeExe = Join-Path $appBuild 'bin/Debug/edge-core.exe'
if (-not (Test-Path -LiteralPath $edgeExe)) { throw 'Native executable is missing.' }
$env:PATH = (Join-Path $openssl 'bin') + ';' + $env:PATH
Push-Location $runDir
try {
    & $edgeExe --bind 127.0.0.1 2>&1 | Tee-Object -FilePath 'edge-core-first-start.log'
} finally {
    Pop-Location
}
```

This stays in the foreground. Observe cloud state from another window and
use the implemented Windows console shutdown path when the case is complete.
If native local-listener porting introduces a required option, record that
option in the executed command; do not assume the Linux socket default works.

**Pass:** within 10 minutes the client injects the developer credentials,
authenticates to the bootstrap server, obtains/stores the LwM2M configuration,
and registers through the real shared OpenSSL/PAL path. Logs should reach the
existing message `Edge-core got registered to the cloud` and report
`Endpoint id : ..., name : ...`. Record both identifiers, the actual server
hosts/ports, TLS version and verification outcome where available. KCM
storage must persist under this run directory, with no repeated bootstrap or
certificate-error loop. A TCP connection alone is insufficient.

### C2: verify the same device in the intended cloud account

Open **Device directory > Devices** in the same portal/account. Locate the
Device ID reported by the running client, confirm current registration state
and a recent connection/registration event, and record its resource list.
Correlate the account, device identity and timestamps with C1.

**Pass:** this Windows instance is registered in the intended account; an old
directory entry by itself does not count. Capture the Device ID and current
cloud status. [Cloud-side verification](https://developer.izumanetworks.com/docs/device-management/current/connecting/linux-on-pc.html)

### C3: perform a live cloud-to-device read

Select an advertised readable Device resource, preferably `/3/0/0`
(manufacturer), `/3/0/1` (model) or `/3/0/2` (serial number). Record its expected
value from the test configuration and the exact resource URI.

Issue a fresh read from the portal if supported. If the portal only displays
cached/observed data, use the documented `POST /v2/device-requests/{device-id}`
operation with a `GET` command and a configured result-notification channel.
Use the selected account's API endpoint and authorized credentials. Retrieve
the asynchronous device response, not just an HTTP request acceptance.
[Reading current resource values](https://developer.izumanetworks.com/docs/device-management/current/resources/handle-resource-webapp.html)

**Pass:** within 60 seconds a new device response succeeds and matches the
expected value. Save the request/correlation ID, timestamp, resource URI,
response status and value. A cached portal value is not a live-read pass.
This proves cloud-to-device request handling and the return path without a
protocol translator or any reboot/write operation.

### C4: stop and restart using the same identity storage

Stop cleanly, keep `$runDir/mcc_config` intact, and restart the same binary with
the same working directory and arguments. Use a separate restart log. Do not
pass `--reset-storage`.

**Pass:** within 10 minutes the same Device ID registers again, stored identity
is retained, and C3 succeeds again. Record whether stored LwM2M credentials
were reused or a fallback bootstrap occurred and why. Unexplained identity
changes or repeated reprovisioning fail this case.

### C5: recover from a temporary outbound interruption

Block only this test executable's outbound traffic for 90 seconds, then restore
it. A temporary per-program Windows Firewall rule from a separate elevated
PowerShell session is suitable; its cleanup must run even if the test fails.
Keep the client running, retain KCM, and record interruption/restoration times.
Do not interrupt the operator's portal/login session or disable the host firewall.

The prepared [PowerShell helper](test/windows-core/test-network-outage.ps1)
implements the per-program block, records timestamps, and removes only its
own rules through `finally` and an independent cleanup process. See its
[usage instructions](test/windows-core/README.md#temporary-network-interruption-c5).
The executed helper blocked both test executables at 12:10:44 CDT on October 1,
2026 and verified rule removal at 12:12:18 CDT. The 90-second hold plus firewall
removal took about 94 seconds. Both clients reported network errors and failed
connection attempts during the block. The independent cleanup process verified
no test rules remained. Release renewed its existing registration about 44
seconds after restoration; Debug did so after about 57 seconds. Fresh reads
succeeded in both, with no process restart or storage reset. This clears C5.
The helper was also corrected for Windows PowerShell 5.1's JSON array behavior.

**Pass:** the running client recovers without manual restart or credential
reset within 15 minutes of restoration, returns under the same Device ID and
passes C3 again. The current maximum reconnect backoff is 600 seconds, so a
very short retry deadline would be misleading. If time expires, preserve the
error/retry log and mark the result failed.

### C6: short stability check

Maintain connectivity for 15 minutes after recovery. Perform fresh C3 reads
near the start and end; record crashes, disconnects and repeated bootstrap.

**Pass:** no crash, persistent reconnect loop or identity/storage loss; both
reads succeed. Run C1-C6 with a Debug build, then build Release and repeat using
`bin/Release/edge-core.exe` and a separate baseline run directory.

Executed concurrently for Debug and Release under separate identities and
local listener ports after both had already passed their separate C1-C4 runs.
The timed monitor ran for 901 seconds, from 12:16:13 to 12:31:14 CDT on
October 1, 2026, with 31 samples per process. It recorded no crash, new error,
stderr output or repeated bootstrap. Handle counts stayed between 201 and
202. Fresh `/3/0/1` reads near the start and after the full interval returned
`Native Win32 x64 edge-core`; final matching CoAP GET/CONTENT IDs were 59976
(Debug, 12:31:47 CDT) and 59977 (Release, 12:32:06 CDT). Both clients then
stopped with Ctrl+C and exit code 0. This clears C6.

## Extended checks after the basic pass

| Check | Expected result |
| --- | --- |
| Registration renewal | Passed in Debug and Release after the timer fix: successful `ACK CHANGED` at the configured 45-minute update interval for a 3600-second lifetime, followed by fresh reads. |
| Controlled negative trust test | Use a separate disposable build/storage fixture with an incorrect server CA; authentication fails and no successful registration occurs. Retain verification checks. Do not blacklist the shared account certificate as a test shortcut. |
| Missing/invalid credentials | Missing developer C file fails the build clearly; malformed credentials cannot produce a cloud connectivity pass. Use isolated fixtures. |
| Runtime CBOR/JSON parity | Repeat with BYOC and the existing runtime provisioning formats. The current `edge-tool` requires `--update-resource` even for certificate conversion; resolve that tool prerequisite explicitly before promising a conversion command. Keep updates disabled for connectivity testing. |
| Other Windows targets | Repeat on Windows 11 Pro and Server 2019/2022/2025, including Server Core. Windows IoT LTSC 2021 follows later. |

## Evidence, triage and completion

Retain a sanitized result record alongside the ignored test output:

| Case | Debug | Release | Evidence / elapsed time / defect |
| --- | --- | --- | --- |
| G0 native application ready | Passed | Passed | Developer builds; credential injection; five PAL and four application tests per configuration |
| C1 first bootstrap + registration | Passed | Passed | Shared OpenSSL 3.5.9; native Windows PAL; developer flow; separate baseline directories |
| C2 correct cloud account/device | Passed | Passed | Portal shows registered gateways with the dedicated test certificate |
| C3 live resource read | Passed | Passed | `/3/0/1`; portal value and matching CoAP GET/CONTENT in client logs |
| C4 persistent identity restart | Passed | Passed | Ctrl+C exit 0; each retains its device ID; stored LwM2M credentials reused |
| C5 network recovery | Passed | Passed | Per-program outbound block; cleanup verified; recovery within 57/44 seconds; new live reads under original identities |
| C6 15-minute stability | Passed | Passed | 901 seconds; 31 process samples each; zero errors/bootstrap attempts; fresh end reads; clean exit 0 |

Include exact revisions/build settings, OS/SDK/OpenSSL versions, credential
file hash and certificate ID, device identity, sanitized client logs, cloud
events/status and live-read responses. Keep raw credential material separate.
Classify failures in this order: native build/startup, provisioning/KCM, DNS/TCP,
TLS trust/client authentication, bootstrap, LwM2M registration, resource handling,
then persistence/recovery. A socket probe or local TLS test cannot clear a later
stage. Preserve failed-run storage before attempting a fresh baseline.

Basic connectivity is complete only when G0 and C1-C6 pass in Debug and Release
on Windows 10 Pro x64, with matching client/cloud evidence. Record blocked and
unexecuted cases explicitly. Service/installer readiness is a separate milestone.

After execution, stop the test client, remove its temporary firewall rule and
retain or retire the dedicated cloud device/certificate according to the account
owner's decision. Storage resets apply only to this isolated run directory.
Do not remove production identities or revoke a certificate used by other tests.
