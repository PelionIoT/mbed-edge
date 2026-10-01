# Native Windows build experiment

`edge-core.exe` now builds as a native MSVC x64 console application in Debug
and Release. Windows selects the same OpenSSL crypto and TLS sources as
upstream, with the existing PAL interfaces for operating-system services.
The developer cloud flow passes bootstrap, registration, fresh resource reads,
identity persistence, network recovery and stability checks on Windows 10 Pro.
This remains an incomplete production port: translator integration, Windows
service lifecycle and installation still need validation or development.

## Source baseline

`experiment/win10support` was created from local `master` at
`64e615230f467fb42fc29730a8f0acd71ca4bcaf`. The upstream default branch is
`master`; there is no upstream `main`. On 2026-09-30 the Windows branches
integrated Edge `776361f77aebaeda581bb4e09e6310874d377498` and its cloud-client
dependency `81c38f3582528628f156a0a58cc10cb000584425`.

The seven incoming Edge commits are retained in merge history:

| Commit | Change | Windows integration |
| --- | --- | --- |
| `9d61e6a` | JSON provisioning generates KCM | Shared sources retained; full application validation remains. |
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
shutdown on that loop. This is console lifecycle handling; SCM support is
still required for running as a Windows service.

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

All five PAL/common tests and all four developer application tests pass in
Debug and Release on this Windows 10 host. The earlier BYOC milestone also
passed its four console tests, including fresh unprovisioned startup. A
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

The next production work is SCM lifecycle handling, a
restricted service identity, Windows/file logging and offline/headless
installer packaging. Firmware updating and privileged reboot handling remain
later work. Windows 11, Server Core and other required editions still need
their own build/runtime validation.
