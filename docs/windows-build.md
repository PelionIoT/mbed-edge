# Native Windows build experiment

`edge-core.exe` now builds as a native MSVC x64 console application in Debug
and Release. Windows selects the same OpenSSL crypto and TLS sources as
upstream, with the existing PAL interfaces for operating-system services.
The developer cloud flow passes bootstrap, registration, fresh resource reads,
identity persistence, network recovery and stability checks on Windows 10 Pro.
The native SCM adapter and restricted-service setup are described below.
Translator integration, release packaging and broader Windows qualification
remain incomplete.

## Source baseline

`experiment/win10support` was created from local `master` at
`64e615230f467fb42fc29730a8f0acd71ca4bcaf`. The upstream default branch is
`master`; there is no upstream `main`. On 2026-09-30 the Windows branches
integrated Edge `776361f77aebaeda581bb4e09e6310874d377498` and its cloud-client
dependency `81c38f3582528628f156a0a58cc10cb000584425`.

The seven incoming Edge commits are retained in merge history:

| Commit | Change | Windows integration |
| --- | --- | --- |
| `9d61e6a` | JSON provisioning generates KCM | Shared FCC/KCM schema retained; Windows uses a PAL-based JSON adapter with relative DER paths. |
| `f9c49f8` | File-based Root of Trust | Uses Windows PAL file APIs for UTF-8 paths. |
| `98ac0fd` | OpenSSL crypto and TLS support | Windows defaults to this shared backend. |
| `76f359a` | File descriptor limit documentation | Retained. |
| `85b5440` | Cloud-client update | Merge its pinned revision with the Windows PAL branch. |
| `643a542` | GCC 13 and duplicate declaration fixes | Retained. |
| `776361f` | File-based Root of Trust opt-in | `ROT_FROM_FILE` remains off by default on Windows too. |

The cloud-client merge includes five incoming commits covering release updates,
the OpenSSL backend, file-based Root of Trust and its include-order fix. The
Edge gitlink points to the resulting cloud-client merge, preserving Windows PAL.

## Build commands

Prerequisites are Visual Studio 2022 C++ Build Tools, a Windows SDK, CMake 3.22
or newer, a native x64 OpenSSL 3.x development SDK (headers, import libraries
and DLLs), and the repository's initialized submodules. The helper can locate
CMake bundled with Visual Studio when it is absent from `PATH`. For the main
project's older dependencies, use CMake 3.x or pass
`-CMakeArgument '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'` with CMake 4.x.

From PowerShell at the repository root:

```powershell
$openssl = 'C:/path/to/native-openssl-sdk'
.\build-windows.ps1 -ConfigureOnly -OpenSSLRoot $openssl
.\build-windows.ps1 -Configuration Debug -OpenSSLRoot $openssl
.\build-windows.ps1 -CoreTests -Configuration Release -OpenSSLRoot $openssl
```

The default output directory is `build/windows-x64`. The helper selects BYOC
provisioning and disables firmware updates and documentation for this initial
attempt. These are development settings, not a reduced final feature scope.
Custom CMake arguments can be passed with `-CMakeArgument`. OpenSSL is selected
explicitly so an older build cache cannot silently retain the mbedTLS default.
`-OpenSSLRoot` sets CMake's `OPENSSL_ROOT_DIR`; omit it if CMake can discover the
SDK. The application's post-build step copies `event.dll`, `event_core.dll`
and the OpenSSL 3 DLLs from the supplied SDK's `bin` directory alongside
`bin/<Configuration>/edge-core.exe`. Keep these files together when running it.
For an SDK installed elsewhere or discovered automatically, ensure its shared
DLLs are available to the application's process. Debug also needs the Visual
Studio debug runtime; Release needs the matching x64 Visual C++ runtime.
Redistributable packaging remains installer work. CTest sets the OpenSSL
tests' process PATH when `-OpenSSLRoot` is supplied.
The helper defaults to one MSBuild worker. Increase this with `-Jobs` on hosts
where parallel MSBuild works correctly. This build environment failed to
coordinate parallel workers; a single worker produces normal compiler errors.

The helper normalizes duplicate `Path`/`PATH` environment entries in the child
process. Without this, some launchers cause MSBuild's compiler detection to
fail with a duplicate dictionary-key error even with a valid MSVC installation.

## Initial result

The attempt on 2026-09-24 used MSVC 19.44.35229, CMake 3.31.6, and the Windows
10.0.26100.0 SDK. C and C++ compiler detection succeeded, and an x64 compiler
probe compiled and linked successfully. After the build-configuration fixes,
`build-windows.ps1 -ConfigureOnly` completed configuration but failed generation
with exit code 1 because these PAL source files were absent:

```text
OS_Specific/Windows/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c
OS_Specific/Windows/Storage/FileSystem/pal_plat_fileSystem.c
OS_Specific/Windows/Networking/pal_plat_network.c
```

CMake consequently could not generate the `palRTOS`, `palFilesystem`, and
`palNetworking` targets. The RTOS implementation file was also required by the
source list. The initial configure log is `build/windows-configure-retry.log`.
The PAL work described below resolves that generation failure. Linux regression
validation has not been run on this host.

## Porting boundary

Keep operating-system changes in Windows-specific files or platform guards.
Use the existing cloud-client PAL contracts and its `ns-hal-pal` event loop.
The selected `OS_BRAND=Windows` now selects implementations under
`mbed-client-pal/Source/Port/Reference-Impl/OS_Specific/Windows`. The cloud-client
submodule has a matching local `experiment/win10support` branch for these
changes. Preserve both repositories' changes when committing this stage.

## PAL implementation and validation

The implementations provide native threads, recursive mutexes, semaphores,
one-shot/periodic timers, monotonic ticks, system entropy, UTF-8 filesystem
paths, and IPv4/IPv6 Winsock UDP/TCP sockets. DNS uses the existing PAL
asynchronous worker around the Windows resolver. Windows uses the `default`
network interface profile and delegates routing to the OS.

The production CMake targets `palRTOS`, `palFilesystem`, `palNetworking`,
`palDRBG` and `crypto-service` build successfully with OpenSSL enabled. Build
these libraries independently of the
remaining application port with:

```powershell
.\build-windows.ps1 -PalOnly -OpenSSLRoot $openssl
```

The original standalone runtime suite passed in Debug and Release on 2026-09-24.
The current suite has five tests, including Edge's Windows common utilities.
They compile the shared OpenSSL TLS and crypto sources and the file-based
Root of Trust implementation. Run them with:

```powershell
.\build-windows.ps1 -PalTests -OpenSSLRoot $openssl
.\build-windows.ps1 -PalTests -Configuration Release -OpenSSLRoot $openssl
```

The suite compiles the actual platform implementations and generic PAL wrappers.
It exercises contention, cancellation, timers and callback deletion, binary file
I/O, Unicode paths, exclusive creation, copy/delete behavior, socket callbacks,
IPv4/IPv6 loopback UDP/TCP, listen/accept, DNS, entropy, and handle cleanup.
Short one-shot timers also cover a lost-wakeup bug found during repeated runs.
The additional checks cover a verified TLS handshake, encrypted loopback echo,
nonblocking handshake retries, mutual client-certificate authentication,
rejection of an untrusted certificate and PAL socket ownership. Crypto checks
use the shared backend for SHA-256 and HMAC
known vectors and OpenSSL random generation. File-based Root of Trust checks
exercise UTF-8 filenames, valid/short/missing keys and metadata path bounds.
Edge common checks cover recursive/error-checking/normal mutex behavior,
contention, monotonic/realtime clocks, formatting/tokenization, file locking,
and binary CBOR input. Missing-file checks include absent parent directories;
PAL file-open returns the same not-found result ESFS expects on Linux.
The tests use local fixtures for KCM metadata and unused legacy event/entropy
hooks; they do not exercise full provisioning, generic DRBG state management or
the application event loop. These are local Windows 10 checks; Server and
Windows 11 validation remains. See [the smoke-test instructions](../test/windows-pal/README.md)
for prerequisites, test output and rerunning without recompiling.

The validation SDK is a workspace-local source build of OpenSSL 3.5.9 from the
official, checksum-verified source archive, configured for `VC-WIN64A` with
`no-asm no-tests no-docs no-apps no-makedepend`. This establishes native build
compatibility; it does not validate a FIPS module or production packaging.
The SDK and build tools under `build/deps` are ignored and are not committed.
Windows storage selects the shared file-backed ESFS/SOTP path; the unused
embedded KVStore dependency no longer pulls mbedTLS into this profile.

On Windows, a platform-guarded OpenSSL BIO calls the existing `pal_send` and
`pal_recv` APIs because Windows PAL socket handles are opaque objects. Linux
keeps its existing descriptor path. Windows currently supports client TLS over
TCP; DTLS and server TLS return `PAL_ERR_NOT_SUPPORTED`.

Current limitations:

- Thread termination is a cooperative cancellation request observed at PAL
  waits/delays. Application loops must cooperate; arbitrary threads are not
  forcibly terminated.
- Timer stop prevents future firings but an already dispatched callback may
  finish. Deletion from another thread waits for that callback; callers must
  not hold locks required by the callback.
- Native socket event callbacks require nonblocking sockets. Blocking sockets
  without callbacks are supported. Explicit adapter binding, connection-status
  callbacks, DNS API 2/3 and IPv6 traffic-class options are not implemented.
- The current PAL `off_t` is 32-bit with MSVC. Position results that cannot fit
  are rejected rather than truncated. Large-file support needs an API decision
  before firmware update support.
- The shared OpenSSL crypto source still emits upstream deprecation,
  size-conversion and type warnings. The smoke tests cover SHA-256, HMAC and
  random generation; other algorithms, CSR/TBS extraction and firmware-update
  crypto require separate validation.
- Flat folder operations preserve subdirectories. Formatting Windows volumes
  and changing the host clock are not supported. The reboot hook exits only
  the process; host reboot needs the later privileged updater and policy.

## Native console milestone

On 2026-10-01 the application built in Debug and Release using MSVC
19.44.35229, Windows SDK 10.0.26100.0, CMake 4.4 and OpenSSL 3.5.9.
`dumpbin` confirms an x64 PE console executable. The Windows C++ profile uses
C++20 for the cloud client's designated initializers; MSVC compatibility
guards cover attributes, array parameters and C linkage. Linux retains its
existing build profile. Linux regression validation has not run on this host.

Edge uses PAL mutexes/semaphores and monotonic ticks on Windows. Its joinable
factory-reset worker uses `_beginthreadex` because PAL threads are detached.
The libevent loop uses Windows thread support, and Ctrl+C/Ctrl+Break queue
shutdown on that loop. Console mode remains available alongside the native
SCM adapter described below.

The protocol API listens on IPv4 loopback. Use
`--edge-pt-address 127.0.0.1:<port>` (default `127.0.0.1:7681`), with the
existing WebSocket/JSON RPC framing. The Linux Unix-socket option is unchanged.
Local TCP currently has no per-user authentication. Restricted Windows IPC
and translator SDK support remain follow-up work before production use.

The bundled libwebsockets/libevent adapter is compiled from a Windows-only
build-directory copy that uses `evutil_socket_t` for callbacks and native
socket handles. The wrapper also supplies Winsock's `timeval` declaration.
The third-party checkout remains unchanged. CMake checks the source patterns
so a future libwebsockets update requires reviewing these corrections.

The first startup exposed a timestamp-logging access violation: without an
explicit `<time.h>`, MSVC implicitly declared `localtime()` and truncated its
pointer on x64. The Windows logger now includes the header, and the application
target rejects implicit C function declarations. Startup also sets Windows
error mode to prevent interactive OS fault dialogs during headless runs.
The missing `event.dll` issue is resolved by copying the concrete libevent
shared targets rather than its interface wrapper.

Run the application smoke tests with:

```powershell
.\build-windows.ps1 -CoreTests -BuildDirectory build/windows-main-merge `
    -OpenSSLRoot $openssl -CMakeArgument '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
.\build-windows.ps1 -CoreTests -Configuration Release `
    -BuildDirectory build/windows-main-merge -OpenSSLRoot $openssl `
    -CMakeArgument '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
```

They check the actual executable's help/version, the bundled native
libwebsockets/libevent loop with a WebSocket handshake and masked-frame echo,
and startup with fresh, unprovisioned storage. The latter expects exit code 1
and `Device not configured for Device Management - exit`, without a crash or
ESFS/factory-reset failure. It is enabled only for the BYOC profile. Test
storage/logs remain under the ignored build directory. No cloud identity or
connection is required. See [the console test instructions](../test/windows-core/README.md).

The developer profile also builds with a private credential C input using
`test/windows-core/build-developer.ps1`. DEBUG CoAP tracing needs a guarded
compile-time buffer bound because MSVC C does not implement variable-length
arrays. Actual credential injection into KCM has passed on this host.

The real cloud attempt exposed an MSVC signed enum bit-field in the shared
client timer: bootstrap timer values 8-11 arrived as -8 through -5. The MSVC
guard preserves the full enum. A new application test sends every timer type
with both zero and nonzero delay through the real nanostack scheduler and
Windows PAL; it failed before the fix and passes afterward.

Windows defaults to ECDHE-ECDSA-AES128-GCM-SHA256 using the same shared OpenSSL
backend. The previous CCM8 default has a 64-bit authentication tag, below the
backend's security level 1 minimum. The TLS fixtures now explicitly exercise
this GCM suite with server trust validation and mutual authentication.
[OpenSSL security levels](https://docs.openssl.org/3.5/man3/SSL_CTX_set_security_level/)
document the minimum security requirements.

The PAL/common suite has passed all five tests in Debug and Release on this
Windows 10 host. Current application builds pass all five developer tests
and all seven BYOC tests in each configuration. The BYOC suite includes fresh
unprovisioned startup and credential-free JSON/PAL regression checks. A
connected translator remains untested. Historical failed build logs remain
under `build/windows-main-merge-full.log`, `build/windows-pal-full-build.log`
and `build/windows-msbuild-diagnostic.log`.

Both Debug and Release developer executables successfully bootstrapped and
registered with the actual cloud on 2026-10-01, using separate identity
directories. The portal showed each new registered gateway and
returned `Native Win32 x64 edge-core` for a fresh `/3/0/1` read, correlated with
the client's CoAP GET/CONTENT trace. Ctrl+C shut down with exit code 0; a restart
reused stored LwM2M credentials and registered with the same cloud device ID.
Private credentials, identity storage, raw logs and portal screenshots remain
under the ignored `build/windows-cloud-connectivity` tree.

The longer cloud run exposed another Windows timer issue: counting periodic
callbacks lost elapsed time when Windows coalesced the wakes. The Windows-only
event clock now advances using elapsed monotonic PAL ticks. A five-second
registration timer with a deliberate callback stall reproduced the drift, then
passed in Debug and Release after the fix. Both cloud clients subsequently
renewed their registrations at the intended 45-minute interval before expiry.

The [developer cloud connectivity plan](../basic-connectivity-test-win10.md)
has passed G0 and C1-C6 in Debug and Release. A temporary per-program firewall
block exercised actual connection loss; both existing processes recovered
without storage resets or manual restarts. A 901-second stability check and
fresh final reads passed, followed by clean stops with exit code 0. Both the
normal firewall cleanup and its independent watchdog verified rule removal.

Production Event Viewer/rotating-file logging and offline/headless release
packaging remain follow-up work. Firmware updating and privileged reboot
handling remain later work. Windows 11, Server Core and other required editions
still need their own build/runtime validation.

## Runtime CBOR and JSON provisioning

The default Windows BYOC build accepts the existing `--cbor-conf` and
`--json-conf` formats and imports them through the shared cloud-client FCC/KCM
path. It uses the same OpenSSL TLS/crypto backend as the developer build.
No developer certificate or private key is compiled into the BYOC executable.
Keep firmware updates disabled for this connectivity profile.

Windows binary input uses the existing PAL filesystem implementation, including
UTF-8 paths and binary reads. The Windows-specific JSON adapter accepts scheme
`0.0.1`, resolves relative DER references against the JSON file's directory,
and checks encoding errors. It supports `Certificates`, `Keys`, `ConfigParams`
and the existing optional `RoTFilePath` field. Malformed/duplicate JSON,
unsupported fields and missing/empty DER files fail before credential import.
The JSON input limit is 1 MiB and the converted bundle limit is 16 MiB.
Supplying both provisioning options is rejected before storage initialization.
Linux retains its existing JSON converter.

For a developer-cloud parity test, `windows/convert-developer-provisioning.py`
uses the existing `edge-tool` schema/key mapping to prepare CBOR and a JSON
bundle with relative DER sidecars. It checks that the EC certificate and key
match. Run it on the build/provisioning host using the Python dependencies in
`edge-tool/requirements.txt`; target machines need no Python. Create an empty
output directory and restrict its ACL to its provisioning operator,
Administrators and SYSTEM before conversion:

```powershell
python .\windows\convert-developer-provisioning.py `
    --credential-file .\build\windows-cloud-connectivity\credentials\mbed_cloud_dev_credentials.c `
    --output-directory D:\factory\private-bundle
```

The output contains private key material: `provisioning.cbor`,
`provisioning.json` and three DER files. `conversion.json` contains provenance
and hashes only. The converter neither prints key values nor creates firmware
update credentials. Keep these test artifacts outside Git and protect retained
FCC/KCM state. This helper creates a developer test bundle, not a production
certificate-enrollment system.

Install a self-contained bundle from local media with the BYOC Release build:

```powershell
.\windows\install-service.ps1 `
    -BinaryDirectory .\build\windows-x64\bin\Release `
    -ProvisioningFile D:\factory\private-bundle\provisioning.json -Start
```

The installer copies CBOR directly. For JSON it validates local DER source
paths, copies the referenced files to protected `config`, and writes UTF-8 JSON
with relative references to those installed copies. Initial bootstrap requires
outbound cloud connectivity; installation itself makes no network requests.
After successful import, ordinary restarts reuse stored credentials even when
the original provisioning input is unavailable. Do not use `--reset-storage`
on an existing identity to test that behavior.

Build both BYOC configurations with `-CoreTests`, then run the four-case matrix
from elevated Windows PowerShell 5.1 with a new evidence directory:

```powershell
.\test\windows-core\test-runtime-provisioning.ps1 `
    -BuildDirectory D:\work\mbed-edge\build\windows-x64 `
    -CredentialDirectory D:\factory\private-bundle `
    -OutputDirectory D:\work\mbed-edge\build\runtime-test-1 `
    -OfflineStartup
```

This checks CBOR and JSON in Release and Debug under restricted LocalService,
then withholds each installed provisioning input and requires the same cloud
identity after restart. It also reruns SCM/ACL/failure tests; optional
`-OfflineStartup` checks local readiness and clean stop without cloud traffic.
It never reboots the host. Services and temporary firewall rules are removed;
protected configuration, state and evidence are retained.

Qualified on 2026-10-01 on Windows 10 Pro 22H2 x64 (19045.6466), Windows
PowerShell 5.1 and shared OpenSSL 3.5.9. Both CBOR and JSON pass in Release and
Debug with developer mode off. Each case bootstraps/registers under restricted
LocalService, starts and stops while outbound traffic is blocked, then
reconnects with the same stored identity while its provisioning input is
withheld. JSON registration uses the installer's staged DER files. Clean
stops report application exit code 0. The matrix also passes the SCM fixture,
including the configured 25-second per-service preshutdown timeout.

Evidence is retained under the ignored
`build/windows-runtime-provisioning/service-matrix-20261001-183022` directory:
overall and per-case `results.json`, progress, copied logs and firewall cleanup
records. Temporary services and rules are removed; credentials and identity
files remain protected. This qualifies runtime bootstrap and persistence on
the tested host. Portal live reads, network recovery while the same process
continues running, renewal and soak were previously qualified with the developer
console profile; those extended cases have not been repeated with BYOC.

## Native Windows service and restricted identity

Windows builds use `edge-core/windows/edge_service.c` for the SCM dispatcher.
Normal invocation retains console behavior. `--service` runs a single native
service process and requires an existing absolute local `--data-dir`. The
optional `--service-name` defaults to `EdgeCore`; `--service-log` selects an
absolute append-only diagnostic log (default: `<data-dir>/service.log`). Paths
with spaces and Unicode are passed through native wide-character APIs.

The adapter reports START_PENDING checkpoints after real initialization steps,
then RUNNING after the local event loop and listeners are ready. Cloud
registration remains asynchronous, so loss of internet does not prevent the
service from starting. STOP, SHUTDOWN and PRESHUTDOWN queue the existing graceful stop on
the libevent thread. Cloud replies are given up to ten seconds before local
teardown proceeds. A twenty-second outer deadline reports failure and terminates
the service process if teardown hangs. Startup/application errors are reported
to SCM, including existing provisioning paths that call `exit(1)`.
The installer sets a per-service preshutdown timeout of 25 seconds, allowing
the 20-second application deadline to finish before normal OS shutdown. It
does not change the machine-wide shutdown timeout. See
[Microsoft's preshutdown behavior](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info).

Service mode verifies its actual process token before opening state: it must
run as `NT AUTHORITY\LocalService`, contain its own enabled and restricted
service SID, and have no privileges beyond `SeChangeNotifyPrivilege`. An
accidentally elevated or unrestricted service fails with access denied.
Console mode does not impose that service-token requirement.

An exclusive `edge-core.lock` in the selected data directory prevents two
processes from using the same persisted identity. Existing PAL filesystem
implementations are reused: relative mount paths resolve beneath the explicit
state directory instead of SCM's working directory. Keep the standard Windows
relative PAL mount configuration when building this profile. Writable data
directories are excluded from subsequent DLL searches.
Console runs without `--data-dir` also lock their existing working directory.

`windows/install-service.ps1` is an offline service-registration/setup helper,
not an MSI or a completed upgrade installer. Run it from elevated Windows
PowerShell 5.1+ after building and staging the runtime dependencies:

```powershell
.\windows\install-service.ps1 `
    -BinaryDirectory .\build\windows-main-merge\bin\Release
Start-Service EdgeCore
Stop-Service EdgeCore
.\windows\install-service.ps1 -Action Uninstall
```

The defaults install to `%ProgramFiles%\Izuma\EdgeCore` and store data in
`%ProgramData%\Izuma\EdgeCore`. Installation uses LocalService, a restricted
per-service SID, a minimal privilege allowlist, delayed automatic startup and
SCM recovery (two restart attempts, then no further action until reset). Only
SYSTEM and Administrators get full control. The service SID gets read/execute
access to binaries and configuration and Modify access to `state` and `logs`.
Ordinary users and other LocalService services receive no data ACL grant.
Inherited OWNER RIGHTS entries also suppress implicit owner permission to
change ACLs on files created by the shared LocalService account, following
[Microsoft's owner-rights semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab).
Provisioning files may be supplied with `-ProvisioningFile <absolute .cbor/.json>`;
the corresponding BYOC build feature must be enabled. JSON sidecars are staged
as described above. No credentials are downloaded by this helper. A developer
build remains a development-only artifact.

Use `-StartupType Manual` to suppress automatic startup for laboratory tests.
Use `-ServiceName`, `-InstallDirectory`, `-DataDirectory`, `-HttpPort` and
`-ProtocolPort` for distinct installations. Installation requires an empty,
dedicated binary directory and separate dedicated data directory; it rejects
reparse points. Uninstall stops/removes the service but retains all binaries,
configuration, logs and persisted identity. Existing state can be secured and
reused by a later installation of the same service name. Staged upgrades and
rollback are not implemented yet.

For reproducible integration tests, build with `-CoreTests`, then run the
following in an elevated PowerShell prompt. It creates uniquely named test
services, exercises the production SCM adapter with a native fixture, and
removes its services even on failure. The output directory must not yet exist.

```powershell
.\test\windows-core\test-service.ps1 `
    -BinaryDirectory .\build\windows-main-merge\bin\Release `
    -OutputDirectory D:\work\mbed-edge\build\service-test-release `
    -RealCloud
```

`-RealCloud` additionally tests real Edge cloud registration and identity
persistence under the restricted service account; use either a developer build
or a BYOC build with `-ProvisioningFile`. Runtime provisioning tests withhold the
installed input after registration to verify persisted credentials on restart.
Keep private credentials outside Git. Omit `-RealCloud` for the credential-free SCM/ACL
fixture. The fixture tests protected binary/configuration writes, configuration
reads, own-state writes, denied foreign-state access, concurrent state locking,
clean restart, crash recovery, rejection of LocalSystem, startup error status,
bounded hung shutdown, and retention on uninstall. It deliberately terminates
only its own verified test process for crash recovery. It never reboots the host.
This does not qualify machine reboot/shutdown or the untested Windows editions.
Add `-OfflineStartup` with `-RealCloud` to test local SCM readiness and clean
stop while that executable's outbound cloud traffic is blocked. The existing
firewall helper and independent cleanup watchdog remove only the test's own
per-program rule; firewall profiles must already be enabled.

For actual machine reboot qualification, use the elevated boot helper after
building both developer configurations with the same private credentials:

```powershell
.\test\windows-core\test-service-boot.ps1 -Action Prepare `
    -BuildDirectory D:\work\mbed-edge\build\windows-main-merge `
    -EvidenceDirectory D:\work\mbed-edge\build\boot-test-1
```

Prepare installs uniquely named Release and Debug services with delayed
automatic startup, verifies initial cloud registration, and snapshots their
identity and log offsets. It copies the observer and installer into an
Administrators/SYSTEM-only directory under
`%ProgramData%\Izuma\EdgeCoreBootTests`. A startup task runs that protected
observer as SYSTEM without a user login. Prepare exercises the exact task on
the current boot and requires an `awaiting-reboot` preflight result. The helper
never calls a reboot/shutdown command. A coordinated restart is a separate step.

After a different boot, the observer waits up to five minutes for SCM to start
the services automatically; it never starts them itself. It requires the prior
boot's PRESHUTDOWN control (15), clean exit within 20 seconds, a subsequent
service start, and cloud registration with the same identity. It then removes
only its matching test services and startup task, retaining state and logs.
The sanitized `boot-results.json` in the evidence directory records pass/fail
and cleanup; `prepared.json` records the protected manifest path. To cancel
before reboot, run:

```powershell
.\test\windows-core\test-service-boot.ps1 -Action Cleanup `
    -Manifest <manifest-path-from-prepared.json>
```

One reboot does not qualify Fast Startup power-off/power-on, abrupt power loss,
or disconnected-network boot. Those are additional machine tests. The current
developer binaries contain a private test key and remain development artifacts.

Validation on 2026-10-01: native developer Debug and Release builds each pass
all five console/timer/WebSocket/options tests. BYOC Debug and Release pass
all seven tests, including JSON conversion, unprovisioned startup and state paths containing spaces
and Unicode. Service mode outside SCM is rejected before creating state files.

The elevated service integration matrix passes in both Release and Debug on
Windows 10 Pro 22H2 x64, build 19045.6466, using Windows PowerShell 5.1 and
shared OpenSSL 3.5.9. Each configuration passes the restricted LocalService
token, service SID, privilege allowlist, state writes, configuration reads,
denied binary/configuration writes, denied foreign-state reads, and inherited
owner-rights ACL checks. Explicit-directory and working-directory concurrent
access both fail with sharing error 32. SCM clean stop/start and crash recovery
preserve state. LocalSystem is rejected with access denied; startup failure
propagates service-specific code 42. A deliberately hung shutdown is bounded
at 20 seconds and reports `ERROR_TIMEOUT` (1460) through SCM.

Real Edge registers with the cloud as restricted LocalService, stops with
application exit code 0, and reconnects after SCM restart with the same persisted
identity in both configurations. Uninstall retains identity and logs. All
temporary test services are removed. Ignored evidence directories are
`build/windows-service-verified-release-20261001-170058-e17b3f` and
`build/windows-service-verified-debug-20261001-170058-e17b3f`; each contains
`results.json`, `progress.log`, and copied probe/cloud logs.

This clears the service lifecycle and restricted identity milestone on the
tested Windows 10 host. Machine reboot/shutdown, delayed automatic startup
after boot and Windows 11/Server/Server Core
qualification remain pending.

The current runtime provisioning matrix above also qualifies configuration of
the 25-second preshutdown timeout and offline service startup/stop in all four
BYOC cases. Actual OS delivery of PRESHUTDOWN, the protected SYSTEM observer
preflight and startup after a different boot still need qualification. No
boot-test services or tasks have been installed, and no reboot has occurred.

The service log currently captures appended console diagnostics without
rotation or an Event Viewer provider. The local loopback protocol API also
remains unauthenticated: restricted service identity does not authenticate
translator/admin callers. Those are separate production gaps.
