# Registration recovery before the first cloud registration

## Failure

An October 25 laptop investigation found that a restarted Windows Core instance
attempted a registration UPDATE before it had registered. The SDK pause path
unconditionally selected WithUpdate. NSDL rejected that update before message
allocation, but the SDK reported MemoryFail (10). Core classified error 10 as
non-transient, permanently blocking its native network recovery policy. Later
DNS, route and resume events were discarded. The real SDK and policy reproduced
both failures in isolated fixtures. The earlier process exit which preceded the
new instance remains unexplained; it is separate from the reproduced recovery bug.

## Correction

The shared SDK now selects WithUpdate on pause only when NSDL has a registered
endpoint. Otherwise it preserves full-registration mode. The NSDL interface also
falls back to full registration if any caller asks for an update without an
existing registration. Resource/lifetime updates are applied before that fallback.
Send failures preserve the NSDL allocation-versus-send distinction instead of
labeling every failure as memory exhaustion. Timer/resource-triggered failures
retain SDK connection-error recovery.

Core permits runtime memory and missing-registration errors to recover, alongside
the existing transport errors. Actual certificate and configuration failures keep
the existing intervention guard. The reconnect reason is written to service stderr
even when INFO tracing is disabled, so later incidents retain their trigger mask.

Network discovery is still driven exclusively by native notifications: Windows IP
Helper, DNS registry notifications and power callbacks; macOS SystemConfiguration,
routing socket and IOKit power callbacks. No DNS queries, internet probes or
periodic configuration scans were added. Existing one-shot debounce and failed
connection backoff deadlines remain; a healthy idle client has no recovery timer.

## Linux scope

Linux Core does not define EDGE_NETWORK_RECOVERY_ENABLED and does not call the
Windows/macOS reconnect wrapper, so that exact startup OS-event path and the
Core recovery-policy latch do not run on Linux. The SDK pause/alert/update code is
shared without platform guards. Linux SDK users can therefore encounter the
invalid-update defect when pausing before registration or updating after losing
registration. The SDK correction applies on every platform. This change does not
add a Linux native network watcher.

## Regression coverage

The native sdk-registration-recovery test links the real SDK. It captures and
parses CoAP packets entirely in memory, without credentials or a remote server:

- Repeated startup pause calls keep full-registration mode.
- An unregistered update sends a full POST to rd without error 10.
- An accepted registration preserves the normal update path.
- A lost registration falls back to a full registration.
- An NSDL parameter/send failure reports NetworkError rather than MemoryFail.
- The production error classifier allows error 10 followed by DNS/resume to
  dispatch recovery; certificate/configuration errors remain guarded.
- Successful registration leaves the event policy without an idle timer.

The historical Linux edge-client-test also tests the actual production classifier
and policy for runtime errors followed by DNS/resume, plus the configuration guard.
The shared policy suite covers OS changes arriving before the initial retry grace.

Native Windows and macOS test configurations enable the real-SDK test by default.
Linux production builds may opt in with EDGE_REGISTRATION_RECOVERY_TESTS=ON.
Run ctest on the native build directory. The Linux historical mock build retains
its existing edge-client-test entry point and gains the shared policy CTest.

## Laptop qualification

Install the next qualification MSI into the existing family with service startup
held. Back up protected config/state and verify every retained hash before startup.
Use a temporary outbound firewall rule restricted to the new Core executable and
its cloud TCP port to hold the first registration. Generate DNS and route changes
while registration is held, verify native recovery dispatches in the service log,
then restore the rule and settings and verify full cloud registration. Test further
network changes and real suspend/resume using the same Core PID and device identity.
Always restore temporary rules/settings in finally blocks and an independent
watchdog. Test observers may read local IPC and socket tables; production discovery
continues to wait on OS events.

## Completed laptop qualification: 2026-10-25

Qualification MSI 0.21.1040 was installed into the existing laptop qualification
family. The tested Core source is 5ce694c8c11574374c489a7e5b68b98da147f315;
the shared Cloud Client source is 6fa1336e2b4aaf69dbbe5d2219cae8e5d01524ee.
The monitor remains version 0.1.2; its installed payload is byte-identical to the
previous monitor, because this update changes Core/SDK recovery only.

The protected backup was hash-verified. All 35 retained configuration/state files
matched before starting the new service. The existing device identity and the
provisioning CBOR still matched after testing. No credentials were imported or
reset. The installed Core image matched the built payload hash.

| Case | Result |
| --- | --- |
| DNS change before first cloud registration | Native event dispatched in 2.1 seconds while a scoped firewall rule held Core's first registration. |
| Split-route change before first registration | Native event dispatched in 10.5 seconds; still no cloud registration. |
| Release startup hold and restore DNS | Full registration succeeded in 9.0 seconds with retained identity. |
| DNS change and restoration after registration | New registered connections in 8.3 and 11.0 seconds. |
| Split-route addition and removal after registration | New registered connections in 8.6 and 11.0 seconds. |
| Actual S3 suspend/resume | Reconnected in 6.3 seconds after the suspend call returned; native recovery mask included resume. |
| Settled idle interval | Same registered socket remained stable for 30 seconds. |

Core PID 43312 remained unchanged through every qualification case. Windows
Kernel-Power 42/107 and Power-Troubleshooter corroborated actual suspend/resume.
The one-shot wake timer requested 45 seconds; the complete suspend API call,
including transitions/resume, returned after 66.7 seconds. Power-Troubleshooter
recorded sleep at 03:16:35.704 UTC and wake at 03:17:42.101 UTC on October 26.
No power policy was changed.

The temporary firewall rule applied only to the new Core executable's cloud TCP
port. It was removed, the test route was removed, and the original DNS suffix was
restored. Both qualification helpers exited. A subsequent independent IPC check
confirmed connected state, the same PID and original identity. The updated log
contained no unregistered-update, false registration-allocation or TLS socket
failure. Local IPC/socket observations belong only to the qualification harness;
production network discovery still waits on native OS notifications.

Visual Studio 2022 and 2026 each passed all 18 local suites. All seven cross-platform
CI jobs passed, including Windows Debug/Release, macOS 14/26 Debug/Release and the
historical Linux suite. Native macOS runs included the real SDK regression and
passed all 13 CTests. Linux CI covers the historical mock suite and production
error-classifier/policy regressions; a native Linux production SDK fixture was not
run in this qualification. Hardware suspend/resume was tested on this Windows
laptop, not on a Mac. The Windows 10 API target is retained; this hardware run was
on Windows 11. This is functional qualification rather than an endurance run.

CI: https://github.com/PelionIoT/mbed-edge/actions/runs/40260177454

Detailed local evidence:
D:/work/mbed-edge-windows-installer/build/registration-recovery-laptop-20261025/
See result.json, installed-verification.json, build-verification.json and
sleep-wake-times.json. The protected backup is restricted to Administrators/SYSTEM.
