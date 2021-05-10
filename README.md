# Edge

This document contains the instructions for using and developing Edge.

The full Edge documentation is [part of our Device Management documentation site](https://cloud.mbed.com/docs/latest/connecting/device-management-edge.html), where you can also find the [API documentation](https://cloud.mbed.com/docs/current/mbed-edge-api/index.html). For comments or questions about the documentation, please [email us](mailto:support@mbed.org).

## License

This software is provided under Apache 2.0 license.

## Content

The contents of the repository.

### Folders

| Folder name           | Contents
|-----------------------|---------------------------------------------------------
| `cmake`               | CMake scripts
| `common`              | Common functionality of edge-core and pt-client.
| `config`              | The configuration files location.
| `edge-client`         | A wrapper used to integrate Edge with Device Management Client.
| `edge-core`           | Edge Core server process.
| `edge-rpc`            | Common RPC functionality of edge-core and pt-client.
| `edge-tool`           | A helper tool to observe and manipulate Edge mediated resources.
| `fota`                | Firmware update callback function defintions.
| `include`             | Header files for Edge.
| `lib`                 | Edge library dependencies
| `pt-client`           | **Deprecated** Protocol translator client v1 stub.
| `pt-client-2`         | Protocol translator client v2 stub.
| `test`                | Unit tests.

### Files

| File name                         | Description
|-----------------------------------|---------------------------------------------
| `CMakeLists.txt`                  | The root CMakeLists file.
| `git_details.cmake`               | CMake file used for generating the version information.
| `config/mbed_cloud_client_user_config.h` | A configuration file for the Device Management Client settings.
| `config/mbedtls_mbed_client_config.h`    | A configuration file for Mbed TLS.

## Prerequisites

### 1. Install these in Ubuntu 18.04:

```bash
sudo apt install build-essential clang cmake curl doxygen gcc git graphviz libc6-dev libclang-dev libcurl4-openssl-dev libmosquitto-dev mosquitto-clients pkg-config python3 python3-pip python3-venv
```

For debugging, install also these:

```bash
sudo apt install lcov gcovr valgrind
```

For documentation, install also these:

```bash
sudo apt install doxygen graphviz
```

### 2. Initialize repositories

Fetch the Git submodules that are direct dependencies for Edge.
```bash
git submodule update --init --recursive
```

### 3. Install Rust

This is required only when building with Parsec.

```bash
curl https://sh.rustup.rs -sSf | bash -s -- -y

# configure the PATH environment variable
export PATH=$PATH:~/.cargo/bin

# To verify, run
rustc --version
cargo version
```

## Configuring Edge build

You can configure the build options for Device Management Client with the CMake command line
flags.
You can enable `BYOC_MODE` or `DEVELOPER_MODE` by giving a flag `-DBYOC_MODE=ON` or
`-DDEVELOPER_MODE=ON` when creating the CMake build to insert the certificates to
Edge during compilation. For factory provisioning, you need to give the mode
`-DFACTORY_MODE=ON`.

```bash
mkdir build
cd build
cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=OFF ..
make
```

In order to have FIRMWARE_UPDATE enabled (ON) you must run the `manifest-dev-tool` to generate the `update_default_resources.c` file. For more information, see the documentation on [enabling firmware updates](#enabling-firmware-update).

With the `BYOC_MODE` it is possible to inject the Device Management Client configuration as CBOR file. The `--cbor-conf` argument takes the path to CBOR file. The `edge-tool` can be used to convert the C source file Device Management developer credentials file to CBOR format. See the instructions in [`edge-tool/README.md`](./edge-tool/README.md)

Other build flags can also be set with this method.

### Enabling firmware update

To use the firmware update functionality, you must generate a `update_default_resources.c` file.

You can create a `update_default_resources.c` file, using the
[`manifest-dev-tool` utility](https://github.com/PelionIoT/manifest-tool), by running:

```bash
manifest-dev-tool init
```

Move the created `update_default_resources.c` file to the `config` folder.

The command also creates a `.update-certificates` folder, which contains self-signed
certificates that the manifest tool uses to sign resources and the manifest for the firmware update.

<span class="notes">**Note:** The generated certificates are not secure for use
in production environments. Please read the
[Provisioning devices for Device Management documentation](https://cloud.mbed.com/docs/latest/provisioning-process/index.html)
on how to build a resource file and certificates safe for a production environment.</span>

Version 0.15.0 introduces a new Firmware-Over-the-Air (FOTA) Update Framework library which extends the capability of the previous library aka Update Client (UC) Hub. Using the new library you can not only update the device itself but also push update to a component of the device. For instance, you can leverage the features of new library to update the firmware driver of a BLE or a WiFi module connected to the device managed by Pelion. By default, UC Hub library is compiled into the binary. In order to switch to new FOTA library, add this CMake flag `-DFOTA_ENABLE=ON` during build time.

The FOTA Update Framework library uses `curl` to fetch the images. By default, the curl library is statically compiled. We also support dynamic linking and to enable that add this flag - `-DMBED_CLOUD_CLIENT_CURL_DYNAMIC_LINK=ON` during build time.

Hence, to enable the firmware update using new FOTA library and dynamically linking `curl`, pass the CMake `-DFIRMWARE_UPDATE=ON`, `-DFOTA_ENABLE=ON` and `-DMBED_CLOUD_CLIENT_CURL_DYNAMIC_LINK=ON` when you build Edge Core:

```bash
mkdir build
cd build
cmake -D[MODE] -DFIRMWARE_UPDATE=ON -DFOTA_ENABLE=ON -DMBED_CLOUD_CLIENT_CURL_DYNAMIC_LINK=ON ..
make
```

Alternativley, in order to use the UC hub library just compile with CMake `-DFIRMWARE_UPDATE=ON` flag.

In addition, you need to set the `#define MBED_CLOUD_CLIENT_UPDATE_STORAGE`.
The exact value of the define depends on the used Linux distribution and the
machine used to run Edge.
For standard desktop Linux the value is set in `cmake/edge_configure.cmake` to
a value `ARM_UCP_LINUX_GENERIC`.


### Enabling Parsec

[Parsec](https://parallaxsecond.github.io/parsec-book/index.html) is the Platform Abstraction for Security, an open-source initiative, which provides a platform-agnostic interface for calling the secure storage and operation services of a trusted platform module (TPM) on Linux.

This lets you generate the device's bootstrap private key on a TPM during the factory flow. Later, when the device calls the Device Management bootstrap server, Device Management Client calls the Parsec API and uses the bootstrap key as part of the DTLS handshake, without having to export the key.

Now let's try building Parsec client and Edge core. Pass `-DPARSEC_TPM_SE_SUPPORT=ON` when you run the CMake `build` command:

```bash
mkdir build
cd build
cmake -DFACTORY_MODE=ON -DPARSEC_TPM_SE_SUPPORT=ON ..
make
```

Note: You can only work with Edge Core in factory mode when you use Parsec and a TPM.

### Factory provisioning

Factory provisioning is the process of injecting the cryptographic credentials
used to connect Edge to Device Management Cloud. For more information, read the
[Provisioning documentation](https://cloud.mbed.com/docs/latest/provisioning-process/index.html).

### Using your own certificate authority

To use your own certificate authority, add the following flag to the CMake command:
`-DBYOC_MODE=ON`.

After this, you need to add a `byoc_data.h` file filled with the BYOC information to the `edge-client` folder.

### Developer mode

To enable the developer mode, add the following flag to the CMake command:
`-DDEVELOPER_MODE=ON`.

After this, you need to add the `mbed_cloud_dev_credentials.c` file to the
`config` folder. You need a user account in Device Management Cloud to be able to
generate a developer certificate. To obtain the developer certificate, follow
these steps:

 * Go to **Device identity** -> **Security**.
 * Click actions and **Generate developer certificate**
 * Give a name and an optional description to the certificate.
 * Download the certificate file `mbed_cloud_dev_credentials.c`.

### Expiration time configuration

To configure the expiration time from the default of one hour (3600 seconds),
change the compile time define `MBED_CLOUD_CLIENT_LIFETIME` in the
`config/mbed_cloud_client_user_config.h` file. The expiration time is inherited by the
mediated endpoints from the Edge Core. You should set the expiration
time to a meaningful value for your setup. For more the details of the expiration,
read the [Device Management Client documentation](https://cloud.mbed.com/docs/latest/connecting/deregister-your-device.html).

```C
#define MBED_CLOUD_CLIENT_LIFETIME 3600
```

### Configuring the maximum number of registered endpoints

Maximum number of registered endpoints can be configured by giving
`-DEDGE_REGISTERED_ENDPOINT_LIMIT=1000` when creating CMake build.
The default limit is `500` endpoints.

```bash
mkdir build
cd build
cmake -D[MODE] -DFIRMWARE_UPDATE=[ON|OFF] -DEDGE_REGISTERED_ENDPOINT_LIMIT=10 ..
make
```

This value helps to limit the computation and memory resources usage.
When this limit is reached, no more devices can be registered until some devices
unregister.

### Configuring the network interface

To help Edge Core to select the correct network interface, please set the
correct value in the CMake command line `-DEDGE_PRIMARY_NETWORK_INTERFACE_ID=eth0`.
Default value is `eth0`.

```bash
mkdir build
cd build
cmake -D[MODE] -DFIRMWARE_UPDATE=[ON|OFF] -DEDGE_REGISTERED_ENDPOINT_LIMIT=[LIMIT] -DEDGE_PRIMARY_NETWORK_INTERFACE_ID=eth0 ..
make
```
You can find the correct value for example using the Linux command `ifconfig`.
Networking should mostly work with a fake interface ID. However, you need the
correct interface ID for example for the UDP/server like functionality to get the
correct IP address of the interface. Setting this value helps to select the best
network interface if there are several available.

### Configuring the log messages

You change the verbosity of the log messages (useful for debugging) by giving `-DTRACE_LEVEL=DEBUG` when creating the CMake build:

```bash
mkdir build
cd build
cmake -D[MODE] -DTRACE_LEVEL=[DEBUG|INFO|WARN|ERROR] ..
make
```

### Root of Trust device key generation

The Edge versions before `CR-0.4.1` contained a Device Management Client versions
from `1.2.x` which had a defect in Root of Trust device key generation. The
defect is fixed in `1.3.0` version of the Device Management Client but the fix is not
backwards compatible. Use the compatibility flag only if you must have the
compatibility and you accept the security issues it contains.

To preserve the compatibility with devices shipped with earlier versions of the
key generation, a special compiler flag
`PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC` was introduced.
The default behavior is to use the new more secure way of generating the key.

If you want to enable the compatibility the flag has to be defined and the
value of the flag set to `1`.

The flag must be defined in the `cmake/edge-configure.cmake`:

```cmake
add_definitions ("-DPAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC=1")
```

### Using custom targets

Custom targets can be set by creating custom cmake files to `./cmake/targets` and
`./cmake/toolchains`-folders. The `targets`-folder is used for setting up the
Edge build options, whereas the `toolchains`-folder is used for setting the build
environment variables. After creating the custom cmake file, the `./cmake/edge_configure.cmake`
needs to be edited to include the new targets.

### Building Edge Doxygen API

You can use the following commands to build the Doxygen documentation:

```bash
mkdir build-doc
cd build-doc
cmake -DBUILD_DOCUMENTATION=ON ..
make edge-doc
```

The generated documentation can be found from the `build-doc/doxygen`-folder.

### General info for running the binaries

Before running any Protocol Translator clients, start Edge Core first, for example like following:

```bash
./edge-core --edge-pt-domain-socket <domain-socket> -o <http-port>
```

In the `edge-core` command, the `edge-pt-domain-socket` parameter is the domain socket
path where the protocol translator connects to. The `http-port` parameter is the port that you can use for querying the status of Edge.
The default domain socket path is `/tmp/edge.sock` (for the protocol
translator API) and the default HTTP port is `8080` (for the HTTP status API).

To see other command line options, write:

```bash
./edge-core --help
```

When you run the `edge-core` the first time, it creates the folder `./mcc_config` which is
used for persistent storage settings for `egde-core`.

<span class="notes">**Note:** The certificates injected in factory must match this configuration definition.</span>

You can use the `--reset-storage` parameter to clear the settings in this folder
when starting the server. This does not remove the devices and settings in the cloud.
You need to remove them manually, for example using the Device Management Cloud Portal.

You can set the location of the configuration directory in your Edge target configuration file,
for example: `cmake/targets/default.cmake` by changing the values of
`PAL_FS_MOUNT_POINT_PRIMARY` and `PAL_FS_MOUNT_POINT_SECONDARY`.

<span class="notes">**Note:** Do not add trailing `/` to the paths.

For a production device they should be set to
partitions which are persistent between reboots and firmware updates.
Your factory process must be aligned with this setting, it has to use same path.

The primary and secondary mount points may be the same (e.g. for single partition systems).
Recommendation is to use the `/mnt/config/` directory.

If the secondary mount point is different than the primary mount point, it will be used as backup configuration storage.

After starting Edge Core, you can start the protocol translator. It connects
then to Edge Core:

### Protocol translator examples

Some protocol translator example implementations exist. These can be found from their own
[Github repository](https://github.com/PelionIoT/mbed-edge-examples). The repository contains
instructions on building and running the examples.

## Makefile shortcuts for builds and running

At the repository root a Makefile is present with shortcuts to have specific
build templates.

At first it is recommended to run the tests to see that the build environment is
in correct shape: `make run-tests`. When environment is good to go the next
step is to create a developer certificate build: `make build-developer`.

Default Makefile:

* `make [build-developer|build-developer-debug|build-developer-with-coverage|build-byoc|build-factory]` will build the project for
  the specified provisioning .
* `make [run-edge-core|run-edge-core-valgrind|]` runs the Edge Core.
  Pre-condition is one of the builds above.
* `make [run-edge-core-resetting-storage]` runs Edge Core resetting the storage
  i.e. it gives `edge-core` the `--reset-storage` parameter.
  Pre-condition is one of the builds above.

Test Makefile `Makefile.test`:

* `make -f Makefile.test [build-test-byoc|build-test-devmode]` builds and runs tests.
* `make -f Makefile.test [run-tests|run-tests-with-valgrind]` runs the Edge core tests without
  Valgrind or with Valgrind.
* `make -f Makefile.test [run-coverage]` builds, runs tests and collects coverage.

### Running tests and generating and viewing test coverage report manually

The coverage report can be generated by issuing:

```bash
make -f Makefile.test run-coverage
```

To view the report:

```bash
firefox build/coverage.html/index.html
```

### Running the tests with valgrind by issuing

```bash
make -f Makefile.test run-tests-with-valgrind
```

### Debugging with gdb:

Make a debug build so that compiler optimizations are disabled to make
debugging easier. The debug mode can be switched with CMake by giving the
build type `-DCMAKE_BUILD_TYPE=Debug`.

```bash
mkdir build-test
cd build-test
cmake -DBUILD_TARGET=test -DCMAKE_BUILD_TYPE=Debug -D[FLAGS] ..
make
gdb ./bin/edge-core-test
gdb ./bin/pt-client-test
```

### Generating Doxygen

```bash
make build-doc
```

This generates the Doxygen documentation under `build-doc/doxygen` folder.
Run for example: `firefox build-doc/doxygen/index.html &` to view them.
