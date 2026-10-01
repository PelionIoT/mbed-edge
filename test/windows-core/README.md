# Native Windows console smoke tests

From PowerShell in the repository root:

```powershell
$openssl = 'C:/path/to/native-openssl-sdk'
.\build-windows.ps1 -CoreTests -OpenSSLRoot $openssl `
    -CMakeArgument '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
.\build-windows.ps1 -CoreTests -Configuration Release -OpenSSLRoot $openssl `
    -CMakeArgument '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
```

Prerequisites are Visual Studio 2022 C++ Build Tools, a Windows SDK, CMake
3.22 or newer, an x64 OpenSSL 3.x SDK, and initialized repository submodules.
The policy argument is for CMake 4.x and the older bundled dependencies.
The helper builds `edge-core.exe`, copies libevent/OpenSSL DLLs beside it,
and runs CTest. By default the output is `build/windows-x64/bin/Debug` or
`Release`. Debug needs the installed Visual Studio debug runtime; Release
needs the matching x64 Visual C++ runtime.

The tests verify:

- Help and version from the actual native executable.
- A real loopback WebSocket handshake, masked client frame and echoed payload
  using the bundled libwebsockets adapter and Windows libevent loop.
- Immediate and delayed delivery of every client timer type through the shared
  nanostack scheduler and Windows PAL, including the bootstrap stagger timer.
- A five-second registration timer against an independent performance clock,
  including a 1.5-second callback stall, to detect scheduler clock drift.
- Windows service option validation and isolation of explicit state directories.
- Fresh BYOC startup: storage initializes and the timestamp logger prints a
  missing-configuration error, then the process exits normally with code 1.
  This catches startup crashes and missing DLLs without cloud credentials.

The startup check uses an ephemeral HTTP port and a new empty working directory
for every run, preserving its logs/storage under the ignored test build tree.
It is omitted for developer provisioning builds, which may contain credentials.
The transport check binds IPv4 loopback on an OS-assigned port. No service,
cloud connection or administrator privileges are needed for these tests.

To rerun after building:

```powershell
ctest --test-dir build/windows-x64 -C Debug --output-on-failure
```

These checks do not validate a connected protocol translator, JSON RPC
registration or real cloud provisioning. The elevated service tests below
validate the native Windows service separately. Run
the [PAL/common suite](../windows-pal/README.md) separately and follow the
[cloud connectivity plan](../../basic-connectivity-test-win10.md) for a real
developer-certificate test.

To build that developer profile with the downloaded C credential:

```powershell
.\test\windows-core\build-developer.ps1 `
    -CredentialFile build/windows-cloud-connectivity/credentials/mbed_cloud_dev_credentials.c `
    -OpenSSLRoot $openssl
```

The helper checks the expected credential fields without printing their values,
builds with the shared OpenSSL backend, and runs the five CLI/options/transport/timer tests.
It disables firmware updates, file-based RoT and CoAP payload dumps. It does
not start the cloud client automatically. The executable includes the developer
private key; keep the build output and identity storage private and out of Git.

## Temporary network interruption (C5)

`test-network-outage.ps1` blocks outbound traffic for one or two running
`edge-core.exe` test clients for 90 seconds. Run it in an elevated Windows
PowerShell session. It checks each process ID against its executable path,
requires enabled firewall profiles, and creates a unique rule per executable.
It removes the rules in `finally`; an independent cleanup process also checks
them after the outage deadline plus 30 seconds if the main helper terminates.
The helper does not alter firewall profiles or existing rules.

Create a JSON array containing the process IDs and absolute executable paths:

```json
[
  { "processId": 1234, "executable": "D:\\work\\mbed-edge\\build\\windows-x64\\bin\\Debug\\edge-core.exe" }
]
```

Save it under the ignored build directory, create a new empty output directory,
then run:

```powershell
.\test\windows-core\test-network-outage.ps1 `
    -Targets build/windows-cloud-connectivity/recovery-targets.json `
    -ResultsDirectory build/windows-cloud-connectivity/outage-1
```

Read `outage-status.json` for the block/restoration timestamps and
`cleanupVerified`. `firewall-rules.json` records the exact rules; its adjacent
`.cleanup.json` records the independent cleanup result. If cleanup reports an
error, retry only those rules from the same elevated session:

```powershell
.\test\windows-core\test-network-outage.ps1 `
    -CleanupManifest build/windows-cloud-connectivity/outage-1/firewall-rules.json
```

The helper records the interruption, not a connectivity-test pass. Issue a
fresh cloud read during the block to demonstrate loss of the device response,
then verify automatic recovery, the original Device ID, and a fresh successful
read after restoration. Continue with C6's 15-minute stability check. Two
clients must use distinct identity stores and local listener ports.

## Native service and boot qualification

`test-service.ps1` uses the production SCM adapter in a credential-free fixture
to check restricted identity, ACLs, state locking, clean stop/start, recovery,
failure codes, and bounded hung shutdown. `-RealCloud` checks real service
registration and retained identity. `-OfflineStartup` additionally blocks only
the installed test executable and verifies local startup and clean stop without
cloud reachability. It requires `-RealCloud` and enabled firewall profiles.

```powershell
.\test\windows-core\test-service.ps1 `
    -BinaryDirectory D:\work\mbed-edge\build\windows-main-merge\bin\Release `
    -OutputDirectory D:\work\mbed-edge\build\service-test-1 `
    -RealCloud -OfflineStartup
```

Run elevated and choose a new output directory. Services are removed on exit;
logs and state are retained. Actual reboot qualification uses
`test-service-boot.ps1`, which prepares both configurations and a protected
SYSTEM startup observer. It does not reboot the host. Follow the
[boot preparation and cleanup instructions](../../docs/windows-build.md#native-windows-service-and-restricted-identity).
