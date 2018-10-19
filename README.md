# Mbed Edge

This document contains the instructions for using and developing Mbed Edge.

The full Mbed Edge documentation is [part of our Mbed Cloud documentation site](https://cloud.mbed.com/docs/current/connecting/device-management-edge.html), where you can also find the [API documentation](https://cloud.mbed.com/docs/current/mbed-edge-api/index.html). For comments or questions about the documentation, please [email us](mailto:support@mbed.org).

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
| `edge-client`         | A wrapper used to integrate Mbed Edge with Mbed Cloud Client.
| `edge-core`           | Edge Core server process.
| `edge-rpc`            | Common RPC functionality of edge-core and pt-client.
| `edge-tool`           | A helper tool to observe and manipulate Edge mediated resources.
| `include`             | Header files for Mbed Edge.
| `lib`                 | Mbed Edge library dependencies
| `pt-client`           | Protocol translator client stub.

### Files

| File name                         | Description
|-----------------------------------|---------------------------------------------
| `CMakeLists.txt`                  | The root CMakeLists file.
| `git_details.cmake`               | CMake file used for generating the version information.
| `config/mbed_cloud_client_user_config.h` | A configuration file for the Mbed Cloud Client settings.
| `config/mbedtls_mbed_client_config.h`    | A configuration file for Mbed TLS.

## Dependencies

Currently, there are a few dependencies in the build system:

* librt
* libstdc++

Install these in Ubuntu 16.04:

```
$ apt install libc6-dev
$ apt install libmosquitto-dev mosquitto-clients
```

## Build tool dependencies

Tools needed for building:
 * Git for cloning this repository.
 * CMake 2.8 or later.
 * GCC for compiling.

```
$ apt install build-essential cmake git
```

## Initialize repositories

Fetch the Git submodules that are direct dependencies for Mbed Edge.
```
$ git submodule init
$ git submodule update
```

## Configuring Mbed Edge build

You can configure the build options for Mbed Cloud Client with the CMake command line
flags.
You can enable `BYOC_MODE` or `DEVELOPER_MODE` by giving a flag `-DBYOC_MODE=ON` or
`-DDEVELOPER_MODE=ON` when creating the CMake build to insert the certificates to
Mbed Edge during compilation. For factory provisioning, you need to give the mode
`-DFACTORY_MODE=ON`.

```
$ mkdir build
$ cd build
$ cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=OFF ..
$ make
```

In order to have FIRMWARE_UPDATE enabled (ON) you must run the `manifest-tool` to generate the `update_default_resources.c`,
see the documentation on [getting the update resources](#getting-the-update-resources).

With the `BYOC_MODE` it is possible to inject the Mbed Cloud Client configuration as CBOR file. The `--cbor-conf` argument takes the path to CBOR file. The `edge-tool` can be used to convert the C source file Mbed Cloud developer credentials file to CBOR format. See the instructions in [`edge-tool/README.md`](./edge-tool/README.md)

Other build flags can also be set with this method.

### Factory provisioning

Factory provisioning is the process of injecting the cryptographic credentials
used to connect Mbed Edge to Mbed Cloud. For more information, read the
[Provisioning documentation](https://cloud.mbed.com/docs/v1.2/provisioning-process/index.html).

### Using your own certificate authority

To use your own certificate authority, add the following flag to the CMake command:
`-DBYOC_MODE=ON`.

After this, you need to add a `byoc_data.h` file filled with the BYOC information to the `edge-client` folder.

### Developer mode

To enable the developer mode, add the following flag to the CMake command:
`-DDEVELOPER_MODE=ON`.

After this, you need to add the `mbed_cloud_dev_credentials.c` file to the
`config` folder. You need a user account in Mbed Cloud to be able to
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
mediated endpoints from the Mbed Edge Core. You should set the expiration
time to a meaningful value for your setup. For more the details of the expiration,
read the [Mbed Cloud Client documentation](https://cloud.mbed.com/docs/v1.2/connecting/deregister-your-device.html).

```
#define MBED_CLOUD_CLIENT_LIFETIME 3600
```

### Getting the update resources

To enable the firmware update functionality, you need to set the following flag
in the CMake command line: `-DFIRMWARE_UPDATE=ON`.

In addition, you need to set the `#define MBED_CLOUD_CLIENT_UPDATE_STORAGE`.
The exact value of the define depends on the used Linux distribution and the
machine used to run Mbed Edge.
For standard desktop Linux the value is set in `cmake/edge_configure.cmake` to
a value `ARM_UCP_LINUX_GENERIC`.

When you have enabled the update, you need to generate the
`update_default_resources.c` file. To create this file, use the
[`manifest-tool` utility](https://cloud.mbed.com/docs/v1.2/updating-firmware/manifest-tool.html).
Give, for example, the following command:

```
$ manifest-tool init -d "<company domain name>" -m "<product model identifier>"
```

When you have created the file, you need to move it to the `config` folder.
The command also creates the `.update-certificates` folder. This folder contains
the self-signed certificates that are used to sign the resources and can be used
to sign the manifest for the firmware update.

<span class="notes">**Note:** The generated certificates are not secure for use
in production environments. Please read the
[Provisioning devices for Mbed Cloud documentation](https://cloud.mbed.com/docs/latest/provisioning-process/index.html)
on how to build a resource file and certificates safe for a production environment.</span>

### Configuring the maximum number of registered endpoints

Maximum number of registered endpoints can be configured by giving
`-DEDGE_REGISTERED_ENDPOINT_LIMIT=1000` when creating CMake build.
The default limit is `500` endpoints.

```
$ mkdir build
$ cd build
$ cmake -D[MODE] -DFIRMWARE_UPDATE=[ON|OFF] -DEDGE_REGISTERED_ENDPOINT_LIMIT=10 ..
$ make
```

This value helps to limit the computation and memory resources usage.
When this limit is reached, no more devices can be registered until some devices
unregister.

### Configuring the network interface

To help Edge Core to select the correct network interface, please set the
correct value in the CMake command line `-DEDGE_PRIMARY_NETWORK_INTERFACE_ID=eth0`.
Default value is `eth0`.

```
$ mkdir build
$ cd build
$ cmake -D[MODE] -DFIRMWARE_UPDATE=[ON|OFF] -DEDGE_REGISTERED_ENDPOINT_LIMIT=[LIMIT] -DEDGE_PRIMARY_NETWORK_INTERFACE_ID=eth0 ..
$ make
```
You can find the correct value for example using the Linux command `ifconfig`.
Networking should mostly work with a fake interface ID. However, you need the
correct interface ID for example for the UDP/server like functionality to get the
correct IP address of the interface. Setting this value helps to select the best
network interface if there are several available.

## Configuring the log messages

You change the verbosity of the log messages (useful for debugging) by giving `-DTRACE_LEVEL=DEBUG` when creating the CMake build:

```
$ mkdir build
$ cd build
$ cmake -D[MODE] -DTRACE_LEVEL=[DEBUG|INFO|WARN|ERROR] ..
$ make
```

### Root of Trust device key generation

The Mbed Edge versions before `CR-0.4.1` contained a Mbed Cloud Client versions
from `1.2.x` which had a defect in Root of Trust device key generation. The
defect is fixed in `1.3.0` version of the Mbed Cloud Client but the fix is not
backwards compatible. Use the compatibility flag only if you must have the
compatibility and you accept the security issues it contains.

To preserve the compatibility with devices shipped with earlier versions of the
key generation, a special compiler flag
`PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC` was introduced.
The default behavior is to use the new more secure way of generating the key.

If you want to enable the compatibility the flag has to be defined and the
value of the flag set to `1`.

The flag must be defined in the `cmake/edge-configure.cmake`:

```
add_definitions ("-DPAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC=1")
```

### Using custom targets

Custom targets can be set by creating custom cmake files to `./cmake/targets` and
`./cmake/toolchains`-folders. The `targets`-folder is used for setting up the Mbed
Edge build options, whereas the `toolchains`-folder is used for setting the build
environment variables. After creating the custom cmake file, the `./cmake/edge_configure.cmake`
needs to be edited to include the new targets.

### Building the Mbed Edge Core server

You can use the following commands to do a developer build:

```
$ cp [DEVELOPER_CLOUD_CREDENTIALS] config/mbed_cloud_dev_credentials.c
$ mkdir build
$ cd build
$ cmake -DDEVELOPER_MODE=ON ..
$ make
```

The built `edge-core` binary will be in `build/bin`-folder.

### Building Mbed Edge Doxygen API

You can use the following commands to build the Doxygen documentation:

```
$ mkdir build-doc
$ cd build-doc
$ cmake ..
$ make edge-doc
```

The generated documentation can be found from the `build-doc/doxygen`-folder.

### General info for running the binaries
Before running any Protocol Translator clients, start Edge Core first, for example like following:

```
$ ./edge-core --edge-pt-domain-socket <domain-socket> -o <http-port>
```

In the `edge-core` command, the `edge-pt-domain-socket` parameter is the domain socket
path where the protocol translator connects to. The `http-port` parameter is the port that you can use for querying the status of Mbed Edge.
The default domain socket path is `/tmp/edge.sock` (for the protocol
translator API) and the default HTTP port is `8080` (for the HTTP status API).

To see other command line options, write:

```
$ ./edge-core --help
```

When you run the `edge-core` the first time, it creates the folder `./mcc_config` which is
used for persistent storage settings for `egde-core`.

<span class="notes">**Note:** The certificates injected in factory must match this configuration definition.</span>

You can use the `--reset-storage` parameter to clear the settings in this folder
when starting the server. This does not remove the devices and settings in the cloud.
You need to remove them manually, for example using the Mbed Cloud Portal.

You can set the location of the configuration directory in your Edge target configuration file,
for example: `cmake/targets/yocto.cmake` by changing the values of
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
[Github repository](https://github.com/ARMmbed/mbed-edge-examples). The repository contains
instructions on building and running the examples.
