# Windows PT to cloud counter test

This is a portal-assisted end-to-end test against a cloud-connected native
Windows `edge-core.exe`. It uses the JSON-RPC messages from
[the simple JavaScript PT example](https://github.com/PelionIoT/mbed-edge-examples/blob/master/simple-js-examples/simple-pt-example.js)
over Windows loopback TCP. It does not require the Linux C PT SDK, npm packages,
an API key, administrator access, or a new provisioning identity.

## Run

Start an already-provisioned Edge Core build, or use the running Windows service.
Confirm its HTTP `/status` reports `connected`. The default service has HTTP
port 8080 and PT port 7681. Node.js 22 or newer is required.

In a terminal, from the repository root:

```powershell
node test/windows-core/pt-counter.js --output build/pt-cloud-run-1 --initial 1001
```

Use a new output directory for each run. To test a console client on separate
ports, add `--url ws://127.0.0.1:17684/1/pt --status http://127.0.0.1:8082/status`.
The PT reads the actual gateway ID and build version from `/status`, negotiates
`edge_protocol_translator`, registers a unique PT/device name, and creates
one readable Generic Sensor resource `/3300/0/5700`. Its counter is encoded as
an eight-byte big-endian double in Base64, as in the upstream example.

The PT holds each counter value until its cloud observation is recorded. It
fails and unregisters on timeout (default 30 minutes; configurable with
`--max-seconds`). Ctrl+C also attempts unregister and records a failed run.

1. Read `result.json` in the output directory for `gatewayId` and
   `gatewayResourcePath`. Select the matching account and gateway in the portal.
2. Under Resources / Connected device resources, open the new sensor. Its
   complete gateway path is `/d/<deviceId>/3300/0/5700`.
3. Record UTC immediately before clicking the resource's **Refresh** button.
   Wait for the request to finish and compare its numeric value with `counter`.
   Save a screenshot showing the resource path and value in the run directory.
4. Record the observation using the helper below, substituting the actual
   gateway ID, full path, read timestamp, and screenshot filename:

```powershell
.\test\windows-core\control-pt-counter.ps1 -OutputDirectory build/pt-cloud-run-1 `
    -Action Observe -Value 1001 -GatewayId '<gateway ID>' `
    -ResourcePath '/d/<deviceId>/3300/0/5700' `
    -ReadStartedUtc '2026-10-03T06:11:10.969Z' -Screenshot portal-1001.png
```

Check that `result.json` now says `cloud-verified`. Change the counter:

```powershell
.\test\windows-core\control-pt-counter.ps1 -OutputDirectory build/pt-cloud-run-1 `
    -Action Set -Value 1002
```

Wait for the PT's JSON-RPC `write` acknowledgement and `counter-changed` event.
Repeat the fresh portal read and observation for 1002, then set and verify 1003.
The helper queues commands; `events.jsonl` records acknowledgement or rejection.
An observation is rejected if its value, gateway, path, read time, or screenshot
does not match the current update. A new value is rejected until the previous
value has cloud evidence. These checks prevent marking a local RPC success as
an end-to-end pass; the screenshot's content must still be inspected by the
operator or browser agent.

Finish the test:

```powershell
.\test\windows-core\control-pt-counter.ps1 -OutputDirectory build/pt-cloud-run-1 -Action Stop
```

Pass requires the baseline and at least two increasing PT writes verified in
the portal, no transport errors, a successful `device_unregister`, and a clean
WebSocket close. The PT then exits 0 and writes `passed: true` to `result.json`.
Refresh the portal resource list and record whether it still retains cached
resource history. Confirm endpoint removal in the Edge trace and the cloud
registration-update acknowledgement; the portal may retain old resource rows.
Stop any console Edge process started for the test cleanly; keep existing
services and provisioning intact. Retain private logs and screenshots under
the ignored `build/` tree.

## Offline regression

`windows-core-endpoint` is a separate credential-free CTest. It verifies the
actual client endpoint factory, object/resource lookup, counter updates, and
every base/data type in the client's packed fields. This catches MSVC sign
extension that previously changed `ObjectDirectory` (4) to -4, causing the PT
to create an endpoint and then fail to find it during device registration.
The MSVC fields now use four bits; other compilers retain their original layout.
Run the regular `windows-core-tests` target and CTest in Debug and Release.

## Qualification on 2026-10-03

Both native developer builds passed against the actual cloud on Windows 10
Pro x64. Each value below was verified by a fresh portal read, with a matching
CoAP GET/CONTENT exchange in the Edge trace, after the PT registration/write
acknowledgement. The resource was `/d/<unique-device>/3300/0/5700`.

| Configuration | PT values verified in cloud | PT listener | Result |
| --- | --- | --- | --- |
| Debug | 1001, 1002, 1003 | `127.0.0.1:17684` | Passed |
| Release | 2001, 2002, 2003 | `127.0.0.1:17685` | Passed |

Each run completed `device_unregister`, closed its WebSocket, and exited 0.
Edge acknowledged endpoint deletion, and the cloud acknowledged the resulting
registration updates. The portal retained cached resource rows after cleanup;
their presence is not evidence that the removed endpoint is still live.
Both temporary Edge processes then stopped through Ctrl+C with exit 0.
All six developer CTests passed in each configuration, including the new
endpoint regression. A premature counter change was also rejected until its
baseline had cloud evidence.

The initial attempt against installed release `0.21.1002` failed
`device_register` with JSON-RPC error -30000. The subsequent console trace
identified the MSVC enum bitfield defect described above. The successful runs
used rebuilt executables from Edge commit
`62f3a196076c3b1d62082e36f6d8f425b4309789` plus the local client-header fix.
The installed service was kept running its existing binary; this result does
not qualify that older installed package. These runs qualify cloud reads of
PT changes, not an unsolicited notification subscription.

Private evidence remains under the ignored `build/` tree:

- `windows-pt-cloud-debug-fixed-20261003`: result, JSON-RPC events and three portal screenshots.
- `windows-pt-cloud-release-fixed-20261003`: result, JSON-RPC events and three portal screenshots.
- `windows-pt-core-debug-20261003/edge-fixed-stdout.log`: Debug Edge trace.
- `windows-pt-core-release-20261003/edge-stdout.log`: Release Edge trace.
- `windows-pt-ctest-debug.log` and `windows-pt-ctest-release.log`: offline results.
- `windows-pt-cloud-qualification-20261003.json`: result/evidence summary and binary hashes.
