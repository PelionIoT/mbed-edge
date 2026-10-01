# Native Windows build experiment

This is an incomplete port. The Windows PAL adapters now compile as native
MSVC x64 libraries and pass focused runtime tests through the existing PAL
interfaces. Windows selects the same OpenSSL crypto and TLS sources as upstream.
The full application does not yet build or install as a service.

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
```

The default output directory is `build/windows-x64`. The helper selects BYOC
provisioning and disables firmware updates and documentation for this initial
attempt. These are development settings, not a reduced final feature scope.
Custom CMake arguments can be passed with `-CMakeArgument`. OpenSSL is selected
explicitly so an older build cache cannot silently retain the mbedTLS default.
`-OpenSSLRoot` sets CMake's `OPENSSL_ROOT_DIR`; omit it if CMake can discover the
SDK. Ensure the SDK's `bin` directory is on the application's process PATH when
running a binary linked to shared OpenSSL. CTest sets this path for its OpenSSL
tests when `-OpenSSLRoot` is supplied.
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
On 2026-09-30 all four integrated tests passed in Debug and Release against
OpenSSL 3.5.9. They compile the shared OpenSSL TLS and crypto sources and the
file-based Root of Trust implementation. Run them with:

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

## Remaining application build work

CMake now generates the application project. The integrated full build on
2026-09-30 remains unsuccessful. Its log is `build/windows-main-merge-full.log`.
Building it exposes further
MSVC incompatibilities in cloud-client headers (GNU attributes and array
parameter declarations) and POSIX
dependencies in edge-core, including `pthread.h`, `unistd.h`, `sys/socket.h`,
`sys/file.h`, and `arpa/inet.h`. Edge-client and PAL dependencies now guard Linux
link libraries, while remaining application targets still need review.
Historical logs from this stage are under
`build/windows-pal-full-build.log` and `build/windows-msbuild-diagnostic.log`.
The bundled libwebsockets/libevent adapter also emits Windows x64 socket-handle
truncation and pointer/integer warnings that need review before translator
runtime validation.
Its Windows `gettimeofday.c` also fails to compile because `struct timeval`
is undefined.

Windows branches for edge-core and translator SDK calls are the next step.
Disabling libwebsockets' Unix-socket build option does not itself implement the
planned authenticated local Windows transport.

After a working console build, add SCM lifecycle handling, the restricted
service identity, logging, and offline/headless installer packaging. Service,
cloud-bootstrap, provisioning, and translator runtime validation have not yet
been performed. Firmware updating and privileged reboot handling remain later
work.
