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
