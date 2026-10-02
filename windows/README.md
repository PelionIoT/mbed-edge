# Windows runtime and deployment

Native Win32 service, networking, storage and OpenSSL/PAL code belong in
`mbed-edge` and its cloud-client submodule. Build/runtime qualification remains
in [the Windows build guide](../docs/windows-build.md) and
[`test/windows-core`](../test/windows-core/README.md).

Windows packaging, setup, upgrades, first provisioning and deployment tests
now belong in the separate
[mbed-edge-windows-installer repository](https://github.com/IzumaNetworks/mbed-edge-windows-installer).
Use its `windows/build-package.ps1`, `windows/build-installer.ps1` and deployment
instructions. The local checkout is `D:\work\mbed-edge-windows-installer`.
Core service tests accept `-InstallerRepositoryDirectory`; the default is a
sibling checkout named `mbed-edge-windows-installer`.

The installer consumes a native Release BYOC/OpenSSL build and an independently
built monitor from `edge-core-monitor`. It embeds no tenant or device identity.
The tray monitor remains optional and selected by default. Developer and
production CBOR/JSON bundles are external, per-machine provisioning inputs.
Factory-server enrollment and native Windows TPM integration remain later phases.

`convert-developer-provisioning.py` remains here because it converts the shared
Edge developer credential schema for runtime connectivity tests. It creates
developer test bundles, not a production certificate-enrollment system. Its
private inputs/outputs must remain outside Git.
