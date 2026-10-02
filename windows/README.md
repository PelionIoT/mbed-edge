# Windows package deployment

The current deployment bundle contains native Win32 x64 `edge-core.exe`, shared
OpenSSL 3 DLLs, libevent DLLs, Windows PowerShell 5.1 installation/upgrade tools,
license files and an offline Microsoft Visual C++ Redistributable. It requires
a Release BYOC/OpenSSL build with developer mode disabled. Provisioning files,
private keys, imported identities and test executables are excluded.

The offline installer and administrative updater have passed qualification on
Windows 10 Pro 22H2 x64 (19045.6466). The packages produced so far are unsigned
qualification artifacts. Release signing, MSI delivery, clean-image prerequisite
installation and deployment on the other target Windows editions remain pending.

## Build a qualification bundle

Build the native application as described in
[the Windows build guide](../docs/windows-build.md). Supply an original
Microsoft-signed x64 Visual C++ Redistributable and the matching OpenSSL source
directory for its license. The output directory must be new. For example:

```powershell
.\windows\build-package.ps1 `
    -BuildDirectory D:\work\mbed-edge\build\windows-x64 `
    -Version 0.21.1002 `
    -OutputDirectory D:\packages\qualification-2 `
    -VisualCppRedistributable 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Redist\MSVC\14.44.35112\vc_redist.x64.exe' `
    -OpenSSLSourceDirectory D:\work\mbed-edge\build\deps\openssl-3.5.9
```

The helper copies an explicit payload allowlist, creates a manifest with file
sizes and SHA-256 hashes, creates and verifies a Windows file catalog, and
produces a ZIP plus `package-result.json`. It does not need administrator
privileges or accept credential inputs. Packaging uses Windows PowerShell 5.1
catalog cmdlets on a Windows build host. Versions `0.21.1001` and `0.21.1002`
are synthetic deployment versions used for qualification, not official releases.

## Offline and headless installation

Extract the ZIP into a dedicated local directory. Run the installer from an
elevated **64-bit** Windows PowerShell 5.1 session or a trusted management job
running as SYSTEM. For the current unsigned qualification bundle:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File D:\packages\edge-core-0.21.1002-windows-x64\scripts\install-package.ps1 `
    -PackageDirectory D:\packages\edge-core-0.21.1002-windows-x64 `
    -ProvisioningFile D:\factory\private-bundle\provisioning.cbor `
    -AllowUnsigned -Start
```

`-AllowUnsigned` is an explicit qualification override. The normal package
policy requires a valid catalog signature matching a trusted release
certificate supplied through `-SignerThumbprint`. Before executing any elevated
installer, management must independently authenticate the entrypoint and helper
scripts, using signed scripts or a trusted deployment content hash. A check
inside an already executing installer does not establish trust in that script.
Keep the trusted signer/content policy outside the delivered package.

CBOR and JSON provisioning are supported. JSON bundles use staged relative DER
sidecars as described in [runtime provisioning](../docs/windows-build.md#runtime-cbor-and-json-provisioning).
Provisioning is supplied separately from the common package. The target requires
no compiler, Python, source checkout or download during installation. Initial
bootstrap/registration requires the existing outbound cloud connectivity.

Defaults:

| Item | Location/behavior |
| --- | --- |
| SCM service | `EdgeCore`, restricted LocalService, per-service restricted SID, minimal privilege allowlist |
| Binaries | `%ProgramFiles%\Izuma\EdgeCore\releases\<version>` |
| Configuration and persistent identity | `%ProgramData%\Izuma\EdgeCore\config` and `state` |
| Service log | `%ProgramData%\Izuma\EdgeCore\logs` |
| Startup | Delayed automatic; `-Start` also starts it during installation |
| C++ prerequisite | Bundled signed x64 redistributable, `/install /quiet /norestart` if required |

Omit `-Start` to leave a factory installation stopped until it is started
explicitly or Windows next boots. Use `-ServiceName`, `-InstallRoot`,
`-DataDirectory`, `-HttpPort` and `-ProtocolPort` for an isolated qualification
installation. Dedicated local directories are required; reparse points are
rejected. Ordinary users and unrelated LocalService services receive no access
to the protected identity store. The service cannot update its binaries.

The installer accepts prerequisite exit codes 0 and 3010. It returns 3010 when
the prerequisite requests a restart and never restarts the machine itself.
Deployments must handle that return code and coordinate their own restart.

Intune/SCCM can stage the complete extracted bundle and separate private
provisioning bundle, then invoke this script as SYSTEM using 64-bit PowerShell.
A SYSTEM detection script can check the service plus the version in
`%ProgramData%\Izuma\EdgeCore\service-release.json`. Actual Intune/SCCM deployment,
detection/remediation policies and MSI authoring have not yet been qualified.

## Administrative upgrade and rollback

`update-service.ps1` runs as an administrator or SYSTEM, separate from the
restricted client. It is a management-script updater; a resident privileged OTA
updater and the cloud firmware-update path are not implemented by this work.

For an existing qualification installation, supply a newer package and a new
binary directory:

```powershell
.\scripts\update-service.ps1 `
    -ServiceName EdgeCore `
    -PackageDirectory D:\packages\edge-core-0.21.1002-windows-x64 `
    -ReleaseDirectory 'C:\Program Files\Izuma\EdgeCore\releases\0.21.1002' `
    -AllowUnsigned
```

The updater verifies package integrity/signing policy and ownership, rejects a
non-increasing version, stages and protects the new binaries, locks a durable
transaction journal, stops the service cleanly and switches its executable
path. Existing arguments, configuration, logs and identity remain in place.
If the service was running, the updater requires local readiness after restart.
Activation failure restores the previous command, release/installation metadata
and running state. Previous binaries are retained.

`-RequireCloud` additionally requires an initially connected client and the same
cloud identity after activation. This is useful for qualification; an ordinary
offline administrative upgrade does not wait for cloud registration.

An unfinished transaction can be recovered from an elevated prompt:

```powershell
.\scripts\update-service.ps1 -Action Recover -ServiceName EdgeCore
```

Recovery handles `Prepared`, `Switched` and `RolledBack` journal stages and
restores the previous release. It is not a command to downgrade a successfully
completed upgrade. Recovery after forced updater termination or power loss has
not yet been fault-tested. Concurrent external administrative service changes
are rejected. Storage schema migration, release pruning and upgrade handling of
a newly required C++ runtime remain release work; retained old binaries alone
do not establish compatibility with a future storage schema.

Uninstall with `install-service.ps1 -Action Uninstall -ServiceName EdgeCore`.
It removes the service while retaining binaries, configuration, state and logs.
Credential retirement and data deletion are separate operator actions.

## Recorded qualification

On October 1, 2026, shared OpenSSL 3.5.9 and the native BYOC Release build passed:

| Test | Evidence under the ignored `build` directory |
| --- | --- |
| Seven package integrity/profile/signature-policy cases | `windows-package-tests-1/results.json` |
| CBOR install, same-identity upgrade, downgrade rejection and actual SCM failure rollback | `windows-package-service-cbor-20261001-210514/results.json` |
| Equivalent JSON package service qualification | `windows-package-service-json-20261001-210514/results.json` |
| Real restart: Release/Debug × CBOR/JSON, PRESHUTDOWN, automatic startup and same identity | `windows-boot-runtime-20261001-210514/results.json` |

The restart observer ran as SYSTEM after the 21:16 CDT reboot. All four services
stopped cleanly in 516 ms, started automatically after 140.95–142.33 seconds,
and reused their cloud identities with provisioning inputs withheld. Temporary
services and the startup task were removed. See
[the test harness instructions](../test/windows-core/README.md#offline-package-and-upgrade-qualification)
to repeat package tests.

The host already had a newer Visual C++ runtime, so the package tests exercised
the prerequisite version check, not a fresh redistributable installation.
Production release work includes the signing pipeline and trusted script
entrypoint, MSI/management integration, complete redistribution notices and
dependency inventory, clean/offline image installation, interrupted-upgrade
recovery, and Windows 11 Pro/Server 2019/2022/2025 including Server Core.
Windows IoT LTSC 2021 qualification follows later. Fast Startup power cycles,
abrupt loss and disconnected-network boot remain separate lifecycle tests.
