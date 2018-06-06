# Mbed Edge

This document contains the instructions for using and developing Mbed Edge.

The full Mbed Edge documentation is [part of our Mbed Cloud documentation site](https://cloud.mbed.com/docs/current/connecting/mbed-edge.html). For comments or questions about the documentation, please [email us](mailto:support@mbed.org).

## License

This software is provided under Apache 2.0 license.

## Content

The contents of the repository.

### Folders

| Folder name           | Contents
|-----------------------|---------------------------------------------------------
| `build`               | Build files and output.
| `common`              | Common functionality of edge-core and pt-client.
| `doc`                 | Documentation of the source code.
| `edge-client`         | A wrapper used to integrate Mbed Edge with Mbed Cloud Client.
| `edge-core`           | Edge Core server process.
| `edge-module-sources` | Additional modules required by Mbed Edge.
| `edge-rpc`            | Common RPC functionality of edge-core and pt-client.
| `edge-tool`           | A helper tool to observe and manipulate Edge mediated resources.
| `include`             | Header files for Mbed Edge.
| `lib`                 | Git submodules.
| `lorapt-example`      | Protocol translator example for WISE-3610 Lora GW.
| `pt-client`           | Protocol translator client stub.
| `pt-example`          | Protocol translator example implementation.
| `targets`             | Build targets.

### Files

| File name                         | Description
|-----------------------------------|---------------------------------------------
| `build_mbed_edge.sh`              | A helper script to build Mbed Edge with one command.
| `CMakeLists.txt`                  | The root CMakeLists file.
| `git_details.cmake`               | CMake file used for generating the version information.
| `mbed_cloud_client_user_config.h` | A configuration file for the Mbed Cloud Client settings.
| `mbed_client_user_config.h`       | A configuration file for the Mbed Client settings.
| `mbedtls_mbed_client_config.h`    | A configuration file for Mbed TLS.

## Dependencies

Currently, there are a few dependencies in the build system:

* libevent 2.0.21
* libevent-pthreads 2.0.21
* libjansson 2.7
* librt
* libstdc++
* OPTIONAL: libmosquitto (for lorapt-example)

Install these in Ubuntu 16.04:

```
$ apt install libevent-dev libjansson-dev libc6-dev
$ apt install libmosquitto-dev mosquitto-clients
```

## Configuring Mbed Edge build

You can configure the build options for Mbed Cloud Client in the `mbed_edge_config.h`
file, located in `./build/mcc-linux-x86`. You can enable `BYOC_MODE` or `DEVELOPER_MODE`
to insert the certificates to Mbed Edge during compilation. For factory provisioning,
you need to remove the mode (`BYOC_MODE` and `DEVELOPER_MODE`) from the `mbed_edge_config.h`.
You can also use it for other build definitions.

### Factory provisioning

Factory provisioning is the process of injecting the cryptographic credentials
used to connect Mbed Edge to Mbed Cloud. For more information, read the
[Provisioning documentation](https://cloud.mbed.com/docs/v1.2/provisioning-process/index.html).

### Using your own certificate authority

To use your own certificate authority, add the following line to the `mbed_edge_config.h`
file:

```
#define BYOC_MODE 1
```

After this, you need to add a `byoc_data.h` file filled with the BYOC information to the `edge-client` folder.

### Developer mode

To enable the developer mode, add the following line to the `mbed_edge_config.h` file:

```
#define DEVELOPER_MODE 1
```

After this, you need to add the `mbed_cloud_dev_credentials.c` file to the
`edge-client` folder. You need a user account in Mbed Cloud to be able to
generate a developer certificate.

### Expiration time configuration

To configure the expiration time from the default of one hour (3600 seconds),
change the compile time define `MBED_CLOUD_CLIENT_LIFETIME` in the
`mbed_cloud_client_user_config.h` file. The expiration time is inherited by the
mediated endpoints from the Mbed Edge Core. You should set the expiration
time to a meaningful value for your setup. For more the details of the expiration,
read the [Mbed Cloud Client documentation](https://cloud.mbed.com/docs/v1.2/connecting/deregister-your-device.html).

```
#define MBED_CLOUD_CLIENT_LIFETIME 3600
```

### Configuring compilation flags

To configure the compilation flags, edit the `CMAKE_C_FLAGS` variable in the
`targets/mcc-linux-x86/CMake/toolchain.cmake`.

### Using developer certificate from Mbed Cloud

You need a user account in Mbed Cloud to be able to generate developer certificate.

In the Mbed Cloud Portal:

 * Go to **Device identity** -> **Security**.
 * Click actions and **Generate developer certificate**
 * Give a name and an optional description to the certificate.
 * Download the certificate file `mbed_cloud_dev_credentials.c`.
 * Copy the certificate source code file to `edge-client` directory.

### Getting the update resources

To enable the firmware update functionality, you need to set the following flags
in the `mbed_edge_config.h` file:

```
#define MBED_CLOUD_CLIENT_SUPPORT_UPDATE 1
#define MBED_CLOUD_DEV_UPDATE_ID 1
#define MBED_CLOUD_DEV_UPDATE_PSK 1
#define MBED_CLOUD_DEV_UPDATE_CERT 1
```

In addition, you need to set the `#define MBED_CLOUD_CLIENT_UPDATE_STORAGE`.
The exact value of the define depends on the used Linux distribution and the
machine used to run Mbed Edge.

When you have enabled the update, you need to generate the
`update_default_resources.c` file. To create this file, use the
[`manifest-tool` utility](https://cloud.mbed.com/docs/v1.2/updating-firmware/manifest-tool.html).
Give, for example, the following command:

```
$ manifest-tool init -d "<company domain name>" -m "<product model identifier>"
```

When you have created the file, you need to move it to the `edge-client` folder.
The command also creates the `.update-certificates` folder. This folder contains
the self-signed certificates that are used to sign the resources and can be used
to sign the manifest for the firmware update.

<span class="notes">**Note:** The generated certificates are not secure for use
in production environments. Please read the
[Provisioning devices for Mbed Cloud documentation](https://cloud.mbed.com/docs/latest/provisioning-process/index.html)
on how to build a resource file and certificates safe for a production environment.</span>

### Configuring the maximum number of registered endpoints

You can configure the maximum number of registered endpoints in the `mbed_edge_config.h` file:

```
#define EDGE_REGISTERED_ENDPOINT_LIMIT 1000
```

This value helps to limit the computation and memory resources usage.
When this limit is reached, no more devices can be registered until some devices
unregister.

### Configuring the network interface

To help Edge Core to select the correct network interface, please set the
correct value in the `mbed_edge_config.h`:

```
#define EDGE_PRIMARY_NETWORK_INTERFACE_ID "eth0"
```

You can find the correct value for example using the Linux command `ifconfig`.
Networking should mostly work with a fake interface ID. However, you need the
correct interface ID for example for the UDP/server like functionality to get the
correct IP address of the interface. Setting this value helps to select the best
network interface if there are several available.

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

The flag must be defined in the `mbed_edge_config.h`:

```
#define PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC 1
```

### Using custom targets

The repository comes with a toolchain to build for a native Linux machine.
If you want to use a different machine, you should edit the `toolchain.cmake`
file located in the `./targets/mcc-linux-x86/CMake` folder.

### Building executables

You can use the following script to build Mbed Edge:

```
$ ./build_mbed_edge.sh
```

The built binaries are in `build/mcc-linux-x86/existing/bin`.

The following executables will be in the folder:

- `edge-core` - The Mbed Edge Core server.
- `pt-example` - The protocol translator application (example).
- `lorapt-example` - The LoRa protocol translator (example).
(Only built if `libmosquitto` is installed)

You can use the same script to clean the build:

```
$ ./build_mbed_edge.sh --clean
```

### General info for running the binaries

To run the Mbed Edge example, start Edge Core first:

```
$ ./edge-core -p <port> -o <http-port>
```

In the `edge-core` command, the `port` parameter is the port number where the protocol
translator connects to. The `http-port` parameter is the port that you can use
for querying the status of Mbed Edge. The default ports are `22223` (for the protocol
translator API) and `8080` (for the HTTP status API).

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

You can set the location of the configuration directory in the
`mbed_edge_config.h` file by changing the values of
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

```
$ ./pt-example --port <port> --protocol-translator-name <protocol-translator-name>
```

In the pt-example, `port` is the port number where edge-core is waiting for
the connection. `protocol-translator-name` is the name of the protocol translator
connection to Mbed Edge. The default port to connect the protocol translator is `22223`.

To see other command-line options, write:

```
$ ./pt-example --help
```
