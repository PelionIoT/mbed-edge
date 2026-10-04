# Native Windows AF_UNIX counter PT

The native C example connects through Winsock `AF_UNIX`, upgrades to WebSocket
at `/1/pt`, registers a translator/device and changes the readable Generic Sensor
counter `/3300/0/5700`. JSON-RPC methods and big-endian double/Base64 encoding
match the existing TCP PT protocol. It uses Winsock directly instead of the
Linux-oriented C PT SDK.

## Build capability

`EDGE_WINDOWS_TARGET_BUILD` declares the minimum Windows build the executable
targets, independently of the SDK selected by CMake. The provisional default is
17763 (Windows 10 1809 / Server 2019). Builds targeting 17134 or newer compile
the AF_UNIX listener and example when the SDK provides `afunix.h`; an SDK missing
that API is a configuration error. Older targets omit the listener and example.
This compilation rule is not a claim that every Windows SKU has been tested.

Set the minimum explicitly when configuring, for example:

```powershell
cmake -S . -B build/windows-x64 -DEDGE_WINDOWS_TARGET_BUILD=19045
cmake --build build/windows-x64 --config Debug --target windows-core-tests
ctest --test-dir build/windows-x64 -C Debug --output-on-failure
```

Use the normal Windows build prerequisites and provisioning profile described
in [README.md](README.md). The above configuration command reuses an existing
configured build directory. The counter target is `af-unix-counter-pt`.

## Runtime configuration

TCP remains enabled with its existing default `127.0.0.1:7681`. AF_UNIX defaults
to disabled. Copy [windows-runtime.example.json](../../config/windows-runtime.example.json)
and create an operational settings file such as `edge-runtime.json`:

```json
{
  "schemaVersion": 1,
  "pt": {
    "tcpAddress": "127.0.0.1:7681",
    "afUnix": {
      "enabled": true,
      "path": "C:/ProgramData/Izuma/EdgeCoreIPC/pt.sock"
    }
  }
}
```

Start Edge with `--config <file>`, alongside its existing state/provisioning
arguments. This file is separate from `--json-conf`/`--cbor-conf`, which contain
cloud provisioning input. Settings are read at startup; restart to apply edits.
An explicit `--edge-pt-address` argument overrides the settings file's TCP
address. Neither transport falls back to the other after a failure.

The configuration reader rejects unknown keys, duplicate keys, invalid types,
invalid ports, missing enabled-path values and unreadable files before cloud
initialization. An executable built for an older target rejects
`"afUnix": {"enabled": true, ...}` with a capability error; a disabled setting
is accepted. Listener initialization failures also fail startup.

The socket path must be an absolute local drive path fitting 108 UTF-8 bytes,
including its terminating NUL. Its parent directory must already exist.
Use a separate IPC directory and set its ACLs for the actual Edge and PT
identities; do not give PT users access to cloud credential/state directories.
The listener inherits filesystem access controls. Service use requires the
restricted LocalService/service SID to have creation/deletion rights and PTs
to have the required socket access. Default interactive-user access is not
qualification of those service ACLs.

The listener holds an exclusive sibling `.lock` file for its lifetime. It
refuses to replace regular files, directories, unrelated reparse points and
live endpoints. It can recover an abandoned AF_UNIX reparse point after taking
the lock and checking the old endpoint is no longer listening. Normal shutdown
removes the owned socket file and retains the lock file to avoid an ownership
race. Windows AF_UNIX availability is checked by the actual socket creation.

## Run the C PT

From the build's binary directory:

```powershell
.\af-unix-counter-pt.exe --socket C:/ProgramData/Izuma/EdgeCoreIPC/pt.sock --initial 3001
```

The PT prints its unique device ID, full gateway resource path and acknowledged
counter value. Read that resource in the matching gateway's portal Resources
view. Press Enter to increment only after the current value has been verified.
Repeat for two changes, then enter `q` to unregister and close cleanly.

For a quick local run without pausing for cloud reads:

```powershell
.\af-unix-counter-pt.exe --socket C:/ProgramData/Izuma/EdgeCoreIPC/pt.sock `
    --auto --steps 2 --interval-ms 1000
```

The automatic mode verifies JSON-RPC acknowledgements and cleanup; it does not
itself verify cloud values. A transport/RPC failure returns exit code 1.
Argument errors return 2. Successful unregister and WebSocket close return 0.
The example is a bounded educational WebSocket client, not a general WebSocket
SDK: it supports text fragmentation and ping/close frames, uses random masking
keys and validates the upgrade accept/subprotocol, with a 16-KiB message limit
and five-second socket I/O timeouts.

`windows-core-af-unix` runs the actual example against a fixture using the
production listener and bundled libwebsockets. It verifies PT registration,
counter encoding/updates, unregister, failure propagation, Unicode paths,
exclusive ownership and cleanup. `windows-core-runtime-config` verifies settings
validation and the selected build capability. Real Edge/cloud qualification
is a separate test using the interactive example and fresh portal reads.

## Local qualification on 2026-10-03

On Windows 10 Pro 22H2 x64 (19045.6466), the developer Debug and Release builds
passed all eight local tests and the BYOC Debug and Release builds passed all
ten. A build targeting 16299 compiled without the
listener and example, passed the nine BYOC tests, and rejected enabled AF_UNIX
configuration with the capability error. These are build-selection checks on
the current host, not execution on an older Windows installation.

Real cloud-connected Debug and Release Edge instances accepted the native C
PT over AF_UNIX and advertised its counter resource in a cloud registration
update. While those PTs remained connected, a TCP PT successfully registered,
wrote its counter, unregistered and closed cleanly against each Edge instance.
The Debug TCP address came from the JSON file; the Release CLI address correctly
overrode a different JSON address.

The AF_UNIX end-to-end cloud-read test passed in both configurations. Each
baseline and both acknowledged PT writes were read through the cloud portal,
with a matching incoming CoAP GET and outgoing CONTENT response in the Edge
trace for the same resource, message ID and token:

| Configuration | Portal counter values | Cloud GET times (UTC) |
| --- | --- | --- |
| Debug | 3001 → 3002 → 3003 | 23:25:14.488, 23:26:55.391, 23:28:04.441 |
| Release | 4001 → 4002 → 4003 | 23:32:47.545, 23:33:55.241, 23:35:29.498 |

The Debug baseline came from the initial resource-open GET; a subsequent
refresh reused the portal's stored value before the first counter change.
Opening each resource also produced an HTTP 400 from an automatic portal
request, whose cause was not established. Manual reads of the changed values
succeeded. This qualifies cloud resource reads, not unsolicited notifications
or subscriptions.

Both PTs unregistered their devices and completed the WebSocket close with
exit code 0. Both temporary Edge instances then stopped normally with exit code
0, removed their socket files and retained their ownership lock files.
Local evidence is in ignored `build/windows-af-unix-qualification-20261003.json`
and `build/af-unix-cloud-{debug,release}-20261003/`: portal screenshots and
observations, JSON-RPC/cloud traces, read correlations, TCP coexistence and
cleanup results. The report records the tested executable hashes.

The installed Windows service was not changed. Restricted LocalService IPC
directory ACLs, Server and Windows 11 still need separate qualification.
