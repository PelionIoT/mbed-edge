# Native macOS arm64 build

The experimental target supports Apple Silicon and macOS 14 or newer. Its initial feature profile matches the Windows port: BYOC provisioning, OpenSSL, persistent file-backed ESFS/SOTP, cloud networking, and both PT libraries. Firmware updates, factory provisioning, Parsec, and GPIO are rejected at configuration time.

The Darwin PAL changes live in the `lib/mbed-cloud-client` submodule on its matching `port/macos-arm64` branch. They must be published and pinned before this work can be reproduced from a clean remote checkout. The current working tree contains those changes; do not reset that submodule to its older pinned revision during development.

## Build

Install Xcode with a macOS SDK, CMake 3.22 or newer, Perl, and the command-line developer tools. Select a coherent Xcode/SDK pair for this build. Environment settings below affect only these commands.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"

# Build the same checksum-pinned OpenSSL 3.5.9 release used on Windows.
./macos/build-openssl.sh .build-cache/macos-openssl

./build-macos.sh build/macos-release \
  -DOPENSSL_ROOT_DIR="$PWD/.build-cache/macos-openssl/install"
```

The OpenSSL output directory must be new. The script checks its source checksum before extracting or compiling it, builds static libraries, and sets the macOS 14 deployment floor. An intentional dependency update requires both `OPENSSL_VERSION` and `OPENSSL_SHA256` to match the reviewed source release.

`build-macos.sh` defaults to Release and builds Core, both PT libraries, the native provisioning converter, and native tests. Pass additional CMake arguments after the build directory, for example `-DCMAKE_BUILD_TYPE=Debug`. The default macOS target links bundled libevent and OpenSSL statically. Release artifacts must not depend on Homebrew libraries.

Some development hosts have a command-line-tools SDK that differs from their installed Xcode SDK. Supply `DEVELOPER_DIR` or `SDKROOT` as above instead of changing global developer-tool settings.

Configure/build different variants sequentially in one checkout. The existing version-header generator writes into the shared source tree; concurrent configuration can collide even when build directories differ. Independent checkouts avoid that limitation.

## Foreground development

Use an isolated private working directory. The existing PAL mount-point overrides remain available; by default persistent identity lives in `./mcc_config` beneath the process working directory. Darwin PAL creates private directories with mode `0700` and files with mode `0600`, and refuses to follow file symlinks.

```sh
mkdir -m 700 build/macos-run
cd build/macos-run
../macos-release/bin/edge-core --help
```

First enrollment requires a test CBOR or JSON provisioning bundle supplied through `--cbor-conf` or `--json-conf`. Keep that identity separate from production identities. Do not pass `--reset-storage` for a retained identity.

The default PT transport is the Unix domain socket. Optional IPv4 loopback PT uses `--edge-pt-address 127.0.0.1:<port>`; it does not enable TCP status. Give concurrent development instances separate PT socket paths with `--edge-pt-domain-socket`. Status now uses a separate protected Unix HTTP socket, defaulting to `edge-status/status.sock` under the working directory. Its absolute path must fit in 103 UTF-8 bytes. Pass `--status-socket` for a protected directory elsewhere; Core can create its final parent directory, while earlier parents must already exist. TCP status requires explicit `--status-tcp` and a loopback bind address. See [local status](local-status.md) for permissions, limits, and metadata.

After provisioning and local startup:

```sh
curl --unix-socket "$PWD/edge-status/status.sock" http://localhost/status
```

Apple release signing is not required for a foreground cloud connection. Use a
non-production provisioning source with the opt-in check below after building
Core and the sibling monitor console:

```sh
python3 macos/cloud-smoke.py --credentials "$TEST_CREDENTIALS" --format developer
# For an existing FCC bundle, choose --format cbor or --format json.
```

`developer` accepts the portal credentials C file and runs the native converter.
JSON DER/RoT sidecars are copied privately and resolved relative to the original
bundle. Each invocation creates a fresh `0700` directory under `/private/tmp`,
protects copied inputs and logs with `0600`, and leaves the original files alone.
Core runs with separate protected status/PT sockets and TCP status disabled.
The actual monitor console checks its UID/PID and status before accepting a
Connected result. The check stops Core cleanly, restarts without supplying the
bundle again, and requires the same cloud device ID to reconnect. Each run has
a bounded connection deadline; `--timeout` defaults to 180 seconds per startup.

The printed result and private `report.json` omit credentials, device/account
identifiers, server addresses, and raw Core logs. The private directory and its
identity remain available after the check, including on failure. No installed
service or machine account is changed. This is a development check using Python;
installed products retain their native runtime. Connected/reconnected status
does not establish a cloud PT resource exchange: record independent server
confirmation for that release gate.

macOS uses the Windows JSON encoder's schema checks, bounded encoding, and
binary DER handling with POSIX path resolution. Relative DER paths resolve
against the JSON file; absolute local paths are also supported. Malformed
conversion exits before credential import, while retained identity is preserved.

## Validation

The native tests cover counting semaphores, recursive/timed mutexes, cancellation, monotonic clocks, timer restart/stop/delete, deletion during a callback, entropy, persistent files, private storage permissions, IPv4/IPv6 TCP and UDP, DNS failures, routing-based interface selection, repeated initialization, descriptor reuse, and BYOC option parsing. Socket teardown tests cover external close during an active callback and callback self-close. The full build also runs provisioning-converter tests, an isolated unprovisioned Core startup check, real Unix HTTP status and access/lifecycle/limit tests, TLS verification/rejection/mutual authentication, and crypto known-answer tests.

The original nine checks passed in Debug and Release on 2026-10-08 using the Xcode 26.5 SDK and pinned static OpenSSL 3.5.9. The additional JSON provisioning check covers relative/absolute UTF-8 DER paths, binary bytes, large values, 64-bit integers, UUID encoding, and rejection of missing files, duplicate fields, remote references, and malformed schema. The three standalone runtime/network/options checks also passed under ThreadSanitizer. The status checks passed under AddressSanitizer and UndefinedBehaviorSanitizer, including abandoned requests and shutdown with incomplete clients. Release Core records a macOS 14.0 deployment floor; Core and the provisioning converter have only Apple system runtime dependencies. This development-host result does not qualify execution on macOS 14.

PAL tests can be built independently:

```sh
cmake -S test/macos-pal -B build/macos-pal-debug \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DCMAKE_OSX_SYSROOT="$SDKROOT"
cmake --build build/macos-pal-debug --parallel
ctest --test-dir build/macos-pal-debug --output-on-failure
```

For race checking, add `-DCMAKE_C_FLAGS='-fsanitize=thread -fno-omit-frame-pointer'` and `-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=thread` in a separate build directory. Socket tests require permission to bind loopback sockets.

Before release, qualify a real provisioning bundle and PT/cloud resource exchange, cross-account/group Unix status access, monitor service-identity verification, outage recovery, sleep/wake, a clean macOS 14 machine, and Linux/Windows regressions. Repeat TLS and runtime checks on the minimum supported OS. Native monitor/control and setup/installer sources are implemented locally in their sibling repositories on `port/macos-arm64`. Setup includes protected provisioning and journaled activation/rollback; the development package is inspection-only. Journaled uninstall and retained reinstall are also implemented locally. Signed live deployment/uninstall/reinstall, notarization, and clean-host qualification remain required.

## Repeatable port checks

The installer checkout's `validation/validate.py` runs Core, monitor, and setup
Debug/Release checks sequentially, exercises the actual Core status socket with
the console tool, checks CLI refusal paths, and builds/inspects the non-installable
development package. It saves command logs and a JSON report, including source
snapshots, the actual host/toolchain, and explicitly pending release qualification.
See the installer README for the one-command invocation.

`.github/workflows/macos-checks.yml` adds native macOS 14/26 arm64 builds and
unsigned Windows Debug/Release regression tests. Each variant has its own checkout,
so source-generation steps cannot collide. A Linux job explicitly builds and runs
every historical BYOC mock executable; existing Linux workflows continue to apply.
The legacy mock profile selects its CBOR-only API while production retains JSON/CBOR.
Actions are pinned to immutable revisions and no signing credentials are
used. These workflows need the Darwin submodule changes published and pinned;
local authored workflows have not yet run remotely.
