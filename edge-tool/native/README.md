# Native developer provisioning converter

`edge-provision` is a portable C command. It converts portal developer
credentials into the existing FCC `0.0.1` CBOR bundle without compiling or
executing the input source and without changing device identity or services.

```
edge-provision convert-developer --input /path/to/credentials.c --output /private/new-bundle.cbor
```

The filename is unrestricted. The input must contain the twelve
`MBED_CLOUD_DEV_*` declarations used by the portal: device certificate,
bootstrap CA certificate, device EC private key, endpoint name, bootstrap URI,
account ID, manufacturer, model number, serial number, device type, hardware
version, and total memory in KB. Literal byte arrays, adjacent C strings,
standard C byte escapes, integer constants, comments, size declarations, and
the portal include guard are supported. Arbitrary expressions, macro-generated
values, and conditional variants must be resolved before conversion. DER
certificates and the EC private key are parsed and the device key/certificate
match is checked. This checks the bundle's structure, not cloud acceptance.

The output contains private key material. It is created exclusively with a
private ACL on Windows or mode `0600` on POSIX platforms. An existing output
is never overwritten. Keep it out of repositories and logs.

Build independently on Windows, Linux, or macOS with CMake 3.20+, a C99
compiler, and OpenSSL 3 development files:

```
cmake -S edge-tool/native -B build/edge-provision -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build/edge-provision --config Release
ctest --test-dir build/edge-provision -C Release --output-on-failure
```

Windows requires native x64 Visual Studio tools. The signed Windows Core
package includes the command and its app-local dependencies. The Core build
also builds it when the OpenSSL backend and `EDGE_BUILD_PROVISIONING_TOOL`
are enabled. `EDGE_PROVISION_TESTS` controls synthetic credential tests.
