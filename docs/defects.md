# Defects

Known defects in edge-core, with the build they occur on and the evidence that supports them. Each entry carries a status; an entry leaves this file when the fix lands.

## edge-core dies with SIGSEGV on `systemctl stop`

**Status:** open

### Symptom

`systemctl stop` of the edge-core service ends the main process with `SIGSEGV` instead of a clean exit. systemd records the unit as `failed (Result: signal)` rather than `inactive`. The next start succeeds and the gateway registers again, so the crash costs the clean shutdown path and the unit's final state, not the gateway's connectivity.

The crash is intermittent. On the same gateway, four stops in the journal split two ways:

| Stop requested (UTC) | Outcome | Time to exit |
| --- | --- | --- |
| 2026-11-04 20:57:42 | `Failed with result 'signal'` | not captured |
| 2026-11-04 21:52:51 | `Main process exited, code=killed, status=11/SEGV` | 1 s |
| 2026-11-04 21:59:52 | `Deactivated successfully` | 8 s |
| 2026-11-05 03:22:21 | `Deactivated successfully` | 8 s |
| 2026-11-05 16:36:13 | `Main process exited, code=killed, status=11/SEGV` | 3 s |

### Build

- Gateway: `opossum-edge-gw`, an incus VM on Ubuntu 22.04.5 (kernel 5.15.0-202-generic), x86_64, byoc provisioning with the `opossum-edge-gw` certificate on the Izuma staging account.
- Snap: `pelion-edge 3.0.0-dev`, revision `x1`, base `core24`, built from [PelionIoT/snap-pelion-edge](https://github.com/PelionIoT/snap-pelion-edge) `master`, installed with `--devmode`.
- edge-core binary: `/snap/pelion-edge/x1/wigwag/mbed/edge-core-byoc`, reporting `0.21.0-HEAD-df99b7d62295a883ade4c33602c4388207297b99-dirty`.
- Source: this repository at tag `0.21.0` (commit `df99b7d62295a883ade4c33602c4388207297b99`). The snap's `edge-core` part applies the patches in `files/edge-core/patches/0010` through `0018` to edge-core and `0001` through `0005` to `lib/mbed-cloud-client`, strips `-Werror` from the vendored CMake files, and builds with GCC 14 under `-Wno-error=` relaxations for `enum-int-mismatch`, `incompatible-pointer-types`, `implicit-function-declaration`, `int-conversion`, `deprecated-declarations`, `stringop-overflow`, `stringop-overread` and `array-bounds`. The `-dirty` suffix comes from those patches.
- Unit: `snap.pelion-edge.edge-core.service`, `ExecStart=/usr/bin/snap run pelion-edge.edge-core`, `Restart=always`, `RestartSec=5s`, `TimeoutStopSec=30s`, default `KillSignal` (SIGTERM).
- Launcher: `launch-edge-core.sh` execs `edge-core-byoc -o 8081 --cbor-conf /var/snap/pelion-edge/common/device.cbor`.

### Reproduction

Run on the gateway as root. The service has been up for 38 s and the journal shows `Edge-core got registered to the cloud`.

```sh
systemctl status snap.pelion-edge.edge-core.service
#   Active: active (running) since Thu 2026-11-05 16:35:35 UTC
#   Main PID: 583 (edge-core-byoc)

systemctl stop snap.pelion-edge.edge-core.service     # returns 0 after 2.7 s

systemctl status snap.pelion-edge.edge-core.service
#   Active: failed (Result: signal) since Thu 2026-11-05 16:36:16 UTC
#   Process: 583 ExecStart=/usr/bin/snap run pelion-edge.edge-core (code=killed, signal=SEGV)
#   Main PID: 583 (code=killed, signal=SEGV)

systemctl show snap.pelion-edge.edge-core.service -p Result -p ExecMainCode -p ExecMainStatus
# Result=signal ExecMainCode=2 ExecMainStatus=11
```

Journal for the unit over the stop (`journalctl -u snap.pelion-edge.edge-core.service -o short-iso`):

```
2026-11-05T16:36:13+0000 systemd[1]: Stopping Service for snap application pelion-edge.edge-core...
2026-11-05T16:36:16+0000 systemd[1]: snap.pelion-edge.edge-core.service: Main process exited, code=killed, status=11/SEGV
2026-11-05T16:36:16+0000 systemd[1]: snap.pelion-edge.edge-core.service: Failed with result 'signal'.
2026-11-05T16:36:16+0000 systemd[1]: Stopped Service for snap application pelion-edge.edge-core.
```

The dying process writes nothing to the journal between `Stopping` and the SEGV. The earlier crash at 21:52:51 shows the same four lines and the same silence.

For comparison, a clean stop on the same build logs the shutdown path:

```
2026-11-04T21:59:52+0000 systemd[1]: Stopping Service for snap application pelion-edge.edge-core...
2026-11-04T21:59:52+0000 edge-core[28022]: [WARN][serv]: lws_callback_closed: client went away: server wsi 0x558718b3e1c0
2026-11-04T21:59:56+0000 edge-core[28022]: [ERR ][mClt]: M2MNsdlInterface::handle_register_update_response - registration_updated failed
2026-11-04T21:59:56+0000 edge-core[28022]: [INFO][edgecc]: Edge-core got registered to the cloud
2026-11-04T21:59:59+0000 edge-core[28022]: [ERR ][mClt]: M2MNsdlInterface::handle_register_update_response - registration_updated failed
2026-11-04T21:59:59+0000 edge-core[28022]: [INFO][edgecc]: Edge-core got registered to the cloud
2026-11-04T21:59:59+0000 edge-core[28022]: [WARN][edgecc]: edgeclient_destroy: sleeping for 500 ms for shutdown.
2026-11-04T22:00:00+0000 edge-core[28022]: [WARN][rpc ]: Destroyed 0 (unhandled) messages.
2026-11-04T22:00:00+0000 systemd[1]: snap.pelion-edge.edge-core.service: Deactivated successfully.
```

No core dump is available: the VM has no `coredumpctl`, and the kernel log carries no `segfault` line for the process because the snap's AppArmor profile confines it.

After the crash, `systemctl start` brings the unit to `active (running)` within 1 s, edge-core logs `Edge-core got registered to the cloud` for endpoint `01a1a5469b23fe3fdf7d59d200000000`, and `GET https://api.izuma.io/v3/devices/01a1a5469b23fe3fdf7d59d200000000` on the staging account returns `state: registered`.

### Impact

- [PelionIoT/old-pelion-edge-ready-test-suite](https://github.com/PelionIoT/old-pelion-edge-ready-test-suite), `test-cases/l5_system_and_acceptance_tests/system_and_acceptance_tests.js`, `[Level 5] SystemAndAcceptanceTests / EdgeServices / Should return true if snap.pelion-edge.edge-core.service is stopped`. The case runs `sudo systemctl stop <service> && systemctl status <service>` and asserts that the output contains `inactive`; a SEGV stop prints `failed (Result: signal)` and fails the case. On the 2026-11-04 run this is the suite's one failure (105 passed, 1 failed, 24 not run). The sibling `started` and `restarted` cases pass because `Restart=always` and the explicit start both bring the unit back to `active`.
- Every path that stops edge-core through systemd takes the same route: `systemctl restart`, snap refresh, and system shutdown or reboot. A SEGV on the way down skips `edgeclient_destroy`, so the deregistration and the 500 ms thread-drain never run; the gateway re-registers on the next start.
- The edge reboot and factory-reset cases in [PelionIoT/mbed-edge-javaclient](https://github.com/PelionIoT/mbed-edge-javaclient) (gateway PUT and POST cases that fire Reboot, Update and factory reset) are not run against this gateway, so their exposure to this defect is unmeasured.

### Suspected cause

Inferred from the journal and the 0.21.0 source; no backtrace exists yet.

- systemd sends SIGTERM. libevent delivers it to `shutdown_handler` in `edge-core/edge_server.c`, which calls `edgeclient_stop()` in `edge-client/edge_client.cpp`. `edgeclient_stop` removes every protocol translator node and endpoint, and, when the client is `REGISTERED`, sends a register update and waits for `on_registered_callback` to trigger `edgeserver_graceful_shutdown`. Only after the event loop exits does `clean()` call `edgeclient_destroy()`, which logs `edgeclient_destroy: sleeping for 500 ms for shutdown`.
- The clean stops log that `edgeclient_destroy` line about 7 s after `Stopping`, which is the register-update round trip. The crashing stops die 1–3 s after `Stopping` and log nothing from edge-core. The fault therefore sits in the SIGTERM path before `edgeclient_destroy`: inside `edgeclient_stop`, the endpoint and translator teardown it performs, or the mbed-cloud-client callbacks that fire while that teardown is in flight. This is inferred.
- In both crashing stops the preceding minute of the journal carries `M2MNsdlInterface::handle_register_update_response - registration_updated failed` followed by `Edge-core got registered to the cloud`, so a register update is in progress or just finished when SIGTERM arrives. The clean stops carry the same lines, so this is a candidate timing condition, not a confirmed trigger.
- The snap build compiles 0.21.0 and the vendored mbed-cloud-client 4.13.1 with GCC 14 under `-Wno-error=incompatible-pointer-types` and `-Wno-error=int-conversion`, which lets code that older compilers rejected into the binary. Whether any of those sites is the faulting one is unknown.

Next step to confirm: run the same stop with core dumps enabled (`ulimit -c unlimited` under `snap run --shell`, or `systemd-coredump` installed on the gateway) and read the backtrace, or run `edge-core-byoc` under `gdb` outside the unit and send SIGTERM 30–40 s after registration.
