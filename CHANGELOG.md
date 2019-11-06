# Changelog for Edge

## Release 0.11.0 (2019-10-03)

* Pelion Device Management Client library updated to version 3.4.0.
* Mbed TLS updated to version 2.18.1.

## Release 0.10.0 (2019-05-07)

 * Changed Edge to use Device Management Client library default TLS configuration file instead of the TLS configuration file provided by Edge.
   * Removed the now obsolete TLS configuration file (`/config/mbedtls_mbed_client_config.h`).
 * Added KCM certificate `GET` and KCM public key `GET` C APIs.
 * Updated Device Management Client to version 3.3.0.
 * New KCM crypto JSON RPC APIs:
   * `crypto_generate_random` API to generate a random buffer using KCM API.
   * `crypto_asymmetric_sign` API to perform asymmetric sign operation using KCM API.
   * `crypto_asymmetric_verify` API to perform asymmetric verify operation using KCM API.
   * `crypto_ecdh_key_agreement` API to perform ECDH key agreement using KCM API.
 * New KCM crypto PT C APIs:
   * `pt_crypto_generate_random` API to generate a random buffer using KCM API.
   * `pt_crypto_asymmetric_sign` API to perform asymmetric sign operation using KCM API.
   * `pt_crypto_asymmetric_verify` API to perform asymmetric verify operation using KCM API.
   * `pt_crypto_ecdh_key_agreement` API to perform ECDH key agreement operation using KCM API.
 * Changed protocol translator client execute handling to send response through event. This allows sending an execute response payload by setting and writing the resource value inside the execute callback.
 * Added new device certificate renewal PT C APIs to perform certificate renewal or certificate enrollment using CA in cloud:
   * `pt_device_certificate_renew` API to initiate a certificate renewal or enrollment.
   * `pt_free_certificate_chain_context` API to free a certificate chain context passed to the `pt_device_certificate_renew_response_handler`.
   * `pt_device_certificate_renew_finish` API to finish a device certificate renewal or enrollment.
   * `pt_device_certificate_renew_response_handler` callback API prototype for handling the certificate renewal or enrollment result.
   * `pt_device_certificate_renew_request_handler` callback API prototype for handling the certificate renewal or enrollment request sent from the Cloud.

### Bugfixes

 * Added NULL-checks for connection in various API calls. These prevent potential segfaults in situations where connection is missing.
 * Fixed integer request ids in JSON RPC requests.

## Release 0.9.0 (2019-04-19)

 * Added handling for pending JSON RPC requests. Requests are cleaned with an error response if the client
   doesn't respond within the maximum time limit. You can configure this timeout in `cmake/edge_configure.cmake` by modifying
   values `SERVER_REQUEST_TIMEOUT_THRESHOLD_MS` for Edge Core and `CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS` for protocol
   translator C-API v2 client. The entity that made the request receives a `PT_API_REQUEST_TIMEOUT` error response.
 * Added handling for pending JSON RPC requests in the case of disconnection. The entity that made the request receives a `PT_API_REMOTE_DISCONNECTED` error response.
 * Mbed TLS updated to version 2.17.0.
 * Added certificate renewal JSON RPC and C-APIs.
 * Added KCM certificate `get` and KCM public key `get` JSON RPC APIs.
 * Fixed the decoding buffer size in our Base64 library.

### Bugfixes

 * Added test that client sets the disconnect callback in `pt_client_create` in the v2 API.

## Release 0.8.0 (2019-02-27)

 * Updated Mbed TLS to version 2.15.1.
 * Added end-to-end support for asynchronous write operations (`OPERATION_WRITE` and `OPERATION_EXECUTE`) from a web application
   to protocol translator managed endpoints.
   * This allows the web application to detect if the operation has succeeded or failed.
 * CMake 3.5 is required
 * Fixed an issue where a write value operation would allow creating more endpoints than the configured endpoint limit.
 * Fixed a crash occurring when a write value operation is called while the protocol translator is disconnected.
 * Updated Device Management Client to version 2.2.1

## Release 0.7.1 (2019-01-08)

 * Removed `Mbed` from documentation.
 * Removed obsolete injection of insecure RoT module in Edge Core build.
 * Moved the `include/jsonrpc/jsonrpc.h` header under `lib/jsonrpc/jsonrpc`. This header is internal.
 * Moved the `include/edge-rpc/rpc.h` header under `edge-rpc/edge-rpc`. This header is internal.
 * Implemented sending the device unregistration message to Device Management backend. The unregistration relies on the lifetime expiration in the Device Management backend.
 * Updated Device Management Client to version 2.1.1.
 * Implemented Protocol Translator API v2.
   * The old Protocol Translator API (v1) is still available.
   * The v2 API has better thread safety than the v1 API.
   * `ns_list.h` is not visible outside.
   * API uses a connection ID instead of a connection structure pointer.
   * The v2 API optimizes the size of the payload in communication with Device Management Edge.
 * **Deprecated** The Protocol Translator API v1. The API headers deprecated are under `include/pt-client`.
 * Removed Yocto toolchain and target. The build environments need to provide a correct toolchain and target.

### Bugfixes

 * Fixed usage for `--cbor-conf` also when combined with `--reset-storage`.
 * Fixed possible invalid pointer dereference when calling `pt_client_final_cleanup` after `pt_client_start` has returned.
   *Migration note:* The `pt_client_final_cleanup` API functionality has been moved inside the `pt_client_start` function and the `pt_client_final_cleanup` function has been deprecated. Any call to `pt_client_final_cleanup` should be removed and the `pt-client/client.h`" include should be removed from the protocol translator as it is an internal header.
 * Fixed memory leak on `PUT` and `WRITE` request handling. The payload pointer given from Cloud Client to Edge was never freed. The payload was copied for NUL-termination and the original pointer was not freed.
 * Added workaround for waiting Cloud Client threads to stop on Edge Core close. The underlying Cloud Client's EventOS event loop thread is not joined and occasionally it is reported as memory leak by Valgrind.

### Known issues

 * Firmware update from `morty` version of Yocto to `sumo` does not work and makes devices unusable. The differences in the device trees of the different versions cause problems when starting the kernel after the update.
 * When Edge communicates on behalf of multiple devices, there is an underlying limitation in the CoAP communication that effectively reduces the amount of requests in flight to be one. On very heavy communication cases, this introduces extra latency. An example calculation:
   * 30 mediated devices with a resource tree of 20 resources.
   * Round trip time to Mbed Cloud of 200 ms.
   * 10 KB registration message.
   * Underlying Cloud Client sends data in 1 KB blocks and waits for acknowledgement for each block. This equals 10 * 200 ms = 2 seconds.
   * During that time, other messages are not processed.
 * If there are a lot of notification updates passed to Mbed Cloud from Mbed Edge, the responsiveness to requests initiated by Mbed Cloud may be hindered.
 * Protocol translators may cause side effects on devices connecting through another protocol translator if both protocol translators use the same names for the devices because Edge Core identifies the endpoint devices by their name. There is limited checking on which protocol translator owns the endpoint device, and clashing names can cause unknown behavior. Ensure that devices have unique names across the protocol translators. For example, add a prefix or suffix based on the protocol translator name, which must be unique.
 * `DELETE` (CoAP/LwM2M) operation not supported.
 * Devices moving between Edge instances have corner cases that are not supported. Deregister the devices from the current Edge instance before connecting to another Edge instance.
 * Mediated device lifetime tracking is not supported. Devices have the same lifetime as the Edge device. Default is 1 hour. The `#define` used to change the lifetime is `MBED_CLOUD_CLIENT_LIFETIME`.

## Release 0.6.0 (2018-10-19)

 * WISE-3160 content removed.
 * Device Management Edge Local Management API introduced.
 * New command line argument for Edge Core.
   * It is now possible to control the log coloring using the `--color-log` argument.
   * Without the argument, a plain text log is produced.
   * When giving the argument `--color-log` to `edge-core` binary, an ANSI colored log is produced.
 * Added support for setting user data to the `pt_device_t` structure. See `pt_create_device_with_userdata` in
   `pt_api.h.`
 * Removed the duplicate configuration file of Device Management Client.
   * `mbed_client_user_config.h` removed.
   * Moved the TCP keepalive configuration to `mbed_cloud_client_user_config.h`.
 * Renamed LoRa example to MQTT example.
 * Updated the version of Yocto in the Raspberry Pi 3 reference implementation from `morty` to `sumo`.
 * Updated Device Management Client to version 2.0.1.1.
 * Added new fields `account-id` and `lwm2m-server-uri` to Edge status REST API.

### Bugfixes

 * Removed the protocol translator examples from the `edge-core` repository.
   * The examples are now in the [Mbed Edge protocol translator examples repository](https://github.com/ARMmbed/mbed-edge-examples).
 * Added the `libevent_global_shutdown` function to the cleanup stage to prevent occasional memory leaks during shutdown.
 * Fixed issues in JSONRPC message handling on broken messages.

### Known issues

Firmware update from `morty` version of Yocto to `sumo` does not work and makes devices unusable. The differences in the device trees of different versions cause problems when starting the kernel after the update.

## Release 0.5.2 (2018-08-31)

### Bugfixes

 * Implemented fragmented JSONRPC message handling. There was no check if message was fragmented. Fragmentation happened when request payload was exceeding 2048 bytes.

## Release 0.5.1 (2018-07-25)

 * Added CBOR configuration file injection mechanism for `BYOC_MODE`.
   The configuration is injected with `--cbor-conf` command line argument in `edge-core`.
 * Moved `read_file.[c|h]` from `pt-example` to `common`.
 * Added Mbed Cloud developer credentials C source file conversion to CBOR support to `edge-tool`.
 * Updated Mbed Cloud Client to version 1.4.0
 * Prevent enabling the developer update resources if the developer mode is not enabled

## Release 0.5.0 (2018-06-26)

 * Update Mbed Cloud Client to `1.3.3`.
 * **Breaking change** Revised the build system to support normal CMake cycle.
   * Removed pre-generated `build`-directory. Normal out of tree builds are now
     supported.
   * Build helper script `build_mbed_edge.sh` removed.
   * Added `cmake`-directory for predefined CMake configurations.
   * Added `cmake/targets`-directory for predefined build targets.
   * Added `cmake/toolchains`-directory for predefined build toolchains.
 * **Breaking change** Changed underlying communication channel between the Edge Core and protocol translators to use Unix domain socket instead of TCP socket.
 * **Breaking API change** Removed host and port parameters from `pt_client_start()` function and replaced with `socket_path`.
   The underlying communication channel is changed to Unix domain socket.
 * Released JSONRPC API documentation for protocol translators to use.
   The new API is a JSONRPC 2.0 API and uses a websocket as transport.
 * Added simple Javascript protocol translator example to `examples/simple-js-example`.
 * Added `jansson` and `libevent` to libraries.
   Removed runtime and compilation time dependency from environment and operating system.
   These are now built and linked into Mbed Edge binaries in the project.
 * Added `libwebsocket` and `mbedtls` to libraries.
   These are now built and linked into Mbed Edge binaries in the project.
 * Removed `mbed_edge_config.h` from `WISE-3610-SDK` in favor of CMake configuration
   options.
 * Fixed the file path in the documentation for the `update_default_resources.c`.
   Correct folder for the file is `config`.
 * Fix the version information printed by edge-core in product repository.
 * WISE-3610 SDK 1.0.19e support.
 * Improve performance when a lot of endpoints are used.
 * Edge Core check the JSONRPC Protocol API version of Edge Client. If the version doesn't match
   the connection is closed.
 * Implemented a common Trace API which all Edge components use.
 * Removed `common/edge_common.[c|h]`.
 * Changed default for maximum number of registered endpoints limit. New default value is 500.

### Bugfixes

 * Fixed a bug where Edge Core did't decrease the number of allocated endpoints if the Protocol API client was killed.
 * Fixed leaks in edge-core shutdown.
 * Fixed a bug where objects were added twice to Mbed Cloud Client.
 * Fixed a bug when Edge Core could not start when the --reset-storage parameter was used.
 * Fixed Edge Core to return `Edge Core is shutting down` instead of `Internal error` when Edge Core is closing
 * Fixed Edge Core to return `Invalid params` instead of `Error` if deviceId is invalid.
 * Fixed Edge Core crash when it cannot allocate the http port.
 * Fixed registration update behaviour to set the flag to false if resources were added or removed in correct order. The issue was that flag was set to false first and in a nested function call set back to true. This caused unnecessary empty registration updates to Mbed Cloud.

### Known issues

 * Mbed Edge communicates on behalf of multiple devices. There is a underlying limitation
   in the CoAP communication to effectively reduce the amount of requests in flight to
   be one. On very heavy communication cases this will introduce extra latency.
   An example calculation:
   * 30 mediated devices with a resource tree of 20 resources.
   * Round trip time to Mbed Cloud of 200 ms.
   * 10 KB registration message.
   * Underlying Mbed Cloud Client will send data in 1 KB blocks and waits for
     acknowledgement for each block. This equals 10 * 200 ms = 2 seconds.
   * During that time other messages are not processed.
 * If there are lot of notification updates passed to Mbed Cloud from Mbed Edge the
   responsiveness to Mbed Cloud initated requests may be hindered.
 * Protocol translators may cause side-effect on devices connecting through another
   protocol translator if both protocol translators use same names for the devices.
   There is limited checking on the actual protocol translator which owns the
   translated device specified by the name. Ensure that devices have unique names
   across the protocol translators, as an example add a prefix or suffix based on the
   protocol translator name which must be unique.
 * `DELETE` (CoAP/LWM2M) operation not supported.
 * Devices moving between Mbed Edge instances have corner cases that are not supported.
   You should de-register the devices from the current Mbed Edge before connecting to
   an another Mbed Edge.
 * Mediated device lifetime tracking not supported. Devices will have the same lifetime
   as the Mbed Edge device. Default is 1 hour.
   The `#define` to change the lifetime is `MBED_CLOUD_CLIENT_LIFETIME`.
 * Device unregistration to Mbed Cloud uses only the lifetame expiration mechanism.

## Release 0.4.5 (2018-05-04)

 * Updated Mbed Cloud Client version to 1.3.1.1. Which contains following fixes.
   * Linux :RPi3 device gets stuck when rebooting the system after performing firmware
     update.
   * Linux: Update client fix for handling callbacks properly.
   * POST response handling to send the final response only once.

## Release R0.4.4 (2018-04-04)

 * WISE-3610 compilation warnings fixes.
 * Doxygen documentation formatting fixes.
 * Contribution instructions and pull request template added for GitHub community.

### Bugfixes

 * Corrected registration update messages. They were always populated with the
   translated endpoints. This caused a full registration in the Mbed Cloud for
   the translated endpoints. The full registration deletes all subscriptions to
   the endpoints resources. The functionality is now registration update which
   refreshes only the translated device lifetime.

## Release R0.4.3 (2018-03-23)

 * [Mbed Edge Yocto meta layer](https://github.com/ARMmbed/meta-mbed-edge) released.
 * [Mbed RaspberryPi3 Yocto meta layer](https://github.com/ARMmbed/meta-mbed-raspberrypi) released.
 * `protocol_api.c` - fix misleading debug print - `Create resource /d` was printed but actually we were doing a value update.
 * Documented the `lifetime` parameter in `pt_create_device` of `pt-client` API to clearly
   mark the parameter to be reserved and unused.
 * Change default logging level to INFO.

## Known issues

See the release CR-0.4.2 known issue list.

## Release CR-0.4.2 (2018-03-16)

 * Ignore CoAP parse errors from mbed Cloud Client as they are non-critical.
 * Added API's for setting execute and value update callbacks to edge resources.
 * Changed byte order helper functions to use correct conversion functions in `pt-example/byte_order.c`.
 * Add separate configuration header for Mbed Client.

### Known issues

 * Mbed Edge communicates on behalf of multiple devices. There is a underlying limitation
   in the CoAP communication to effectively reduce the amount of requests in flight to
   be one. On very heavy communication cases this will introduce extra latency.
   An example calculation:
   * 30 mediated devices with a resource tree of 20 resources.
   * Round trip time to Mbed Cloud of 200 ms.
   * 10 KB registration message.
   * Underlying Mbed Cloud Client will send data in 1 KB blocks and waits for
     acknowledgement for each block. This equals 10 * 200 ms = 2 seconds.
   * During that time other messages are not processed.
 * If there are lot of notification updates passed to Mbed Cloud from Mbed Edge the
   responsiveness to Mbed Cloud initated requests may be hindered.
 * Binding Mbed Edge core to a already reserved port may cause core dump.
   This is known to happen on Yocto 2.2.x running on Raspberry Pi 3.
 * Protocol translators may cause side-effect on devices connecting through another
   protocol translator if both protocol translators use same names for the devices.
   There is limited checking on the actual protocol translator which owns the
   translated device specified by the name. Ensure that devices have unique names
   across the protocol translators, as an example add a prefix or suffix based on the
   protocol translator name which must be unique.
 * `DELETE` (CoAP/LWM2M) operation not supported.
 * Devices moving between Mbed Edge instances have corner cases that are not supported.
   You should de-register the devices from the current Mbed Edge before connecting to
   an another Mbed Edge.
 * Mediated device lifetime tracking not supported. Devices will have the same lifetime
   as the Mbed Edge device. Default is 1 hour.
   The `#define` to change the lifetime is `MBED_CLOUD_CLIENT_LIFETIME`
 * Device unregistration to Mbed Cloud uses only expiration mechanism currently.
 * Protocol translated device registration through Mbed Edge to Mbed Cloud initiates
   register update message to Mbed Cloud. Mbed Cloud handles the mediated device update
   as full registration. This causes current subscriptions to be dropped to for protocol
   translated resources. Application logic must listen to registration notifications
   and renew subscriptions.

### Bugfixes

 * Add support for empty payload for POST requests from cloud to Edge endpoint.

## Release CR-0.4.1 (2018-03-09)

 * **Backwards incompatible** Root of Trust key derivation fix.
   If the backwards compatibility is needed a define a compiler flag
   `PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC` to value of `1`.
 * Update Mbed Cloud Client to `R1.3.0` release with the dependencies.
   It adds secure time support.
 * Added 3rd party contribution instructions.
 * Added configuration samples and files required by the update feature to the WISE-3610
 * Fixed the file path in the documentation for the `update_default_resources.c`.
   Correct folder for the file is `edge-client`
 * Added configuration samples and files required by the update featur to the WISE-3610.
 * Remove the define `MBED_CLOUD_CLIENT_CONFIG_DIR`. Use `PAL_FS_MOUNT_POINT_PRIMARY`
   and `PAL_FS_MOUNT_POINT_SECONDARY` instead.
 * Edge-core returns an error when trying to registerer a device which is already
   registered. This helps to prevent accidentially modifying the devices owned by
   another edge-core client process.
   This allows more CoAP messages to be stored for resending and duplicate detection.
 * The `edge-tool` to include full message on errors. The Mbed Cloud SDK in some cases
   wraps the status codes to, e.g. `404` to `400`.
 * Added Software One Time Programmed (SOTP) security feature.

### Protocol Translator API

 * Removed resource values from debug logs. Resource value can be pure binary
   data and can break log consumers. The value size is logged instead.

## Release CR-0.4.0 (2018-02-02)

 * **License changed to Apache 2.0**
 * Changed the Edge Core resource value representation to `text-format`.
   This aligns the representation with Mbed Cloud Client and its expected format
   for resource level values. TLV is not yet supported. The values manipulated from
   the Mbed Cloud are in `text-format`.
   See LWM2M technical specification for exact definition of the data types.
   The link between the Protocol Translator and Edge Core uses binary representation
   of the data.
   When protocol translator writes the data to Edge Core:
   * integer, time, float, boolean: network byte-order.
   * string: utf-8.
   * opaque: sequence of binary data.
   * objlink: two 16 bit unsigned integers beside the other.
   When Edge Core writes the data to protocol translator:
   * integer, time, float: network byte-order. The value is 64 bits.
   * string: utf-8.
   * opaque: sequence of binary data.
   * objlink: two 16 bit unsigned integers beside the other.
 * Added a helper tool `edge-tool` for observing, manipulating and filtering resources.
 * Added graceful shutdown support to Edge Core.
 * Edge Core disconnects if client sends invalid JSON.
 * Protocol API error codes are improved to be more consistent / descriptive.
 * Added update client functionality
 * Added maximum number of registered endpoints limit. Default value 1000.
 * Added support to configure the network interface.
 * Added version information to the status API
 * Added support for Reset Factory Settings. Customers may implement their own implementation for RFS in \
   edge-core/edge_server_customer_code.c
 * Fixed issues found by Coverity analysis tool
 * Protocol translator initiated value write and device_register methods improved on error situations.
   The first JSON error is returned and if JSON errors exist, it will not update.
 * Cloud initiated value write made more robust regarding memory buffer handling.

### Protocol translator API

 * **Breaking API change** Removed all global connection variables to make protocol translator API usable from shared library. Causes all API related functions to expect `struct connection *connection` in the arguments.
 * **Breaking API change** The `pt_client_start` function has output reference parameter `struct connection *connection` added. Applications must provide this to protocol translator API functions as argument. This binds the calls to the specific Edge Core connection.
 * **Breaking API change** All protocol translator API functions expect `struct connection *connection` as first argument.
 * **Breaking API change** All protocol translator callback functions expect `struct connection *connection` as first argument.
 * **Breaking API change** Resource values are expected to be given in network byte-order format
   for certain LWM2M value types:
   * integer, time, float, boolean: network byte-order.
 * **Breaking API change** Changed the return type of `pt_received_write_handler` from
   `void` to `int`. It is now possible to return failure from the protocol translator
   implementation.
 * **Breaking API change** `pt_object_instance_add_resource` signature changed.
   The parameter `uint8_t operations` removed. The function will create only a read-only
   resources to the passed object instance.
 * **New API function** Added function to support creating resources with callback.
   The callback is the specified action to do for the resource on WRITE or EXECUTE operation.
   The function name is `pt_object_instance_add_resource_with_callback` and has two
   differences in the signature over the read-only resource creation, `uint8_t operations` and
   `pt_resource_callback callback` function pointer.
   The signature of the resource callback is `typedef void (*pt_resource_callback)(const pt_resource_opaque_t *resource, const uint8_t *value, const uint32_t size, void* userdata)`.
 * Added `parent`-field for `pt_device_t`, `pt_object_t`, `pt_object_instance_t`
   and `pt_resource_opaque_t`.
 * Added an optional helper API `pt-client/pt_device_object.h` for creation standard LWM2M
   device resource object `/3`.

### Protocol translator example

 * Added defaults to command line arguments. Port and host arguments are optional.
   Connects to `127.0.0.1:22223` by default.
 * Updated the protocol translator example:
   * To use network byte-order for float temperatures.
   * to use the changed API when adding resources to object instances.
   * to use the resource callback directly on the resource.
   * IPSO object example to create `/3` device object for the cpu temperature example device.

### LoRa protocol translator example for WISE-3610

 * Added defaults to command line arguments. Port and host arguments are optional.
   Connects to `127.0.0.1:22223` by default.
 * Updated the LoRa protocol translator example to use the changed protocol translator API
   when adding resources to object instances.

### Bugfixes

 * Fixed issues when message was written to client and response came back before the message
   went to request queue. The application were not able to match the response to any request.
   This also caused hidden memory leak, the messages were not removed because response was
   already handled.

## Release CR-0.3.2 (2017-12-27)

 * Updated the version of the factory configurator client
 * Changed the _network_interface to a string in edge-client
 * Removed invalid assert from pt_device_free

## Release CR-0.3.1 (2017-11-14)

 * Release README.md: client_wrapper dir changed to edge-client
 * lorapt-example: mention the command-line parameters in README.md file

## Release CR-0.3.0-EA (2017-11-10)

 * All instances of "Mbed Cloud Edge" changed to "Mbed Edge".
 * Mediated endpoints are can be observed directly.

### Mbed Edge Core

 * Added firmware update client to dependencies and build.
 * The configuration file `mbed_cloud_edge_config.h`is renamed to `mbed_edge_config.h`.
 * Added type definition `protocol_translator_t` for `struct protocol_translator`
 * Splitted `misc_lib.[c|h]` into two reusable functions.
  File `common/integer_length.[c|h]` for calculating integer length as characters.
  File `common/default_message_id_generator.[c|h]` for default implementation of message id generator.
 * Default Mbed Cloud Client Configuration directory is changed from `./pal` to `./mcc_config`. Please read the new instructions in `README.md`.
 * Implemented `POST` and `PUT` support from CoAP to mediated device resources.
   These are translated into `WRITE` and `EXECUTE` operations on LWM2M resources.

### Protocol translator API

 * Introduced new callback (includes device_id) for device related operations
 * **Breaking API change** `pt_client_start` signature changed.
   Removed individual callback function parameters and replaced it with a
   `protocol_translator_callbacks_t` struct to contain all needed callback functions.
 * **Breaking API change** Added a shutdown callback to `pt_client_start` callback structure.
 * **Breaking API change** Added `pt_` namespace to  the callback function prototypes.
 * **Breaking API change** Added `void* userdata` for callback function prototypes.
 * **Breaking API change** Added `hostname` parameter to `pt_client_start`.

### Protocol translator example

 * Updated the example to use the changes in the API's.
 * Protocol translator API moved to run in another thread instead of running in main thread.
 * Devices are contained in list and are persistent during the process runtime.
 * Removed JSON based example application configuration. The JSON file path parameter removed.
 * Example application takes the protocol translator name as second parameter.
 * Added CPU thermal zone thermometer IPSO objects if thermal zone with correct type is available.
 * Example main thread now handles polling to CPU thermal zone for updating thermal zone thermometer IPSO object.
 * Changed example client to use correct IPSO object id (5432 -> 3303) for the simulated thermometer object.
 * Implemented resettable minimum and maximum resources for CPU thermometer object.
  `/3303/0/5601` IPSO object path for minumum measured temperature.
  `/3303/0/5602` IPSO object path for maximum measured temperature.
  `/3303/0/5605` IPSO object path for executable resource to reset minumum and maximum measured temperature.

### LoRa protocol translator example for WISE-3610

 * Updated the example to use the changes in the API's.
 * **Breaking API change** The received write handler signature changed.
   `pt_received_write_handler` exposes the detailed argument list for handling writes and executes.

### Known issues

 * `POST` (CoAP) / `EXECUTE` (LWM2M) operation not supported for other than resources.
 * `PUT` (CoAP) / `WRITE` (LWM2M) operation not supported for other than resources.
 * `DELETE` (CoAP/LWM2M) operation not supported.
 * Devices moving between Mbed Edge instances have corner cases that are not supported.
 * Device unregistration to Mbed Cloud uses only expiration mechanism currently.
 * Mbed Cloud Core does not have hook point to add Mbed Cloud Core specific objects with resources.
 * Notifications from protocol translated resource value changes are currently forwarded only as Mbed Edge value changes and not as connected device value changes.
 * Protocol translated device registration to Core initiates full registration message to Mbed Cloud. This causes current subscriptions to be dropped to for Mbed Edge and protocol translated resources. Application logic must listen to registration notifications and renew subscriptions.
 * Registration update from Core to Mbed Cloud is not supported.

## Release CR-0.2.0-EA (2017-10-13)

### Mbed Edge Core

 * Protocol translator device count resource type changed from `opaque` to `integer`.
 * `client-wrapper` renamed to `edge-client`.
   All API level functions namespaced with `edgeclient_`-prefix.
 * Registration and unregistration error handling added.
 * Registration to Mbed Cloud is deferred if there is one already ongoing.
 * Registration is prevented if Edge Core cannot bootstrap to Mbed Cloud.
 * Show the Mbed Cloud Client error status in HTTP status API response.
 * The Edge Core endpoint name and Mbed Cloud internal id added to HTTP status API response.
 * Fixed deadlock when registering devices and unregistering devices simultaneously.
 * Reduced excessive `info`-level logging.
 * Mbed Cloud Client is allocated dynamically, fixed random SIGSEGV on Edge Core start.
 * Fixed Linux platform stability issues caused by known glibc bug (https://sourceware.org/bugzilla/show_bug.cgi?id=20116). It was manifested by timer implementation in PAL.
 * Edge Core unregisters the devices from Mbed Cloud if it's interrupted using the signal SIGINT.

### Protocol translator API

 * Segmentation fault fixed from protocol translation API when connection cannot be established to Mbed Cloud Core.
 * Added the external endpoint name and internal id to HTTP status API response.
 * **Breaking API change** Refactored the API to be simpler and easier to use.

### Protocol translator example

 * Changed example client to use correct IPSO object id (5432 -> 3300) for the simulated thermometer object.
 * Updated the example client to use refactored API.

### LoRa protocol translator example for WISE-3610

 * Added protocol translator example for WISE-3610 LoRa gateway. See `lorapt-example` directory.

### Known issues

 * `POST` (CoAP) / `EXECUTE` (LWM2M) operation not supported.
 * `DELETE` (CoAP/LWM2M) operation not supported.
 * Devices moving between Mbed Edge instances have corner cases that are not supported.
 * Device unregistration to Mbed Cloud uses only expiration mechanism currently.
 * Mbed Cloud Core does not have hook point to add Mbed Cloud Core specific objects with resources.
 * Notifications from protocol translated resource value changes are currently forwarded only as Mbed Edge value changes and not as connected device value changes.
 * Protocol translated device registration to Core initiates full registration message to Mbed Cloud. This causes current subscriptions to be dropped to for Mbed Edge and protocol translated resources. Application logic must listen to registration notifications and renew subscriptions.
 * Registration update from Core to Mbed Cloud is not supported.

## Release CR-0.1.1-EA (2017-09-12)

### Mbed Edge Core

 * Core to write Mbed Cloud Client errors as errors in log.

### Protocol translator API

 * Segmentation fault fixed when registering multiple resources to an object.

### Known issues

 * See the list of CR-0.1.0-EA

## Release CR-0.1.0-EA (2017-09-06)

### Mbed Edge Core

 * Mbed Edge Core registration as device to Mbed Cloud.
 * Protocol translator registration support.
 * Protocol translated device registration support.
 * Protocol translated device value write support.
   It is possible to write values from protocol translated devices to Core and those values are available in Mbed Cloud.
 * `GET` (CoAP) / `READ` (LWM2M) support for Mbed Cloud Core and protocol translator mediated devices.
 * `PUT` (CoAP) / `WRITE` (LWM2M) support for protocol translator mediated devices.
 * Subscriptions to Mbed Edge resources and protocol translated resources from Mbed Cloud.
 * Status-interface shows other states than "connecting": "connected" when registered to cloud and "error" when encountering an error.

### Protocol translator API

 * Register protocol translator to Core.
 * Register protocol translated device.
 * Unregister protocol translated device.
 * Write values of protocol translated devices to Core.
 * Receive value writes to protocol translated devices from Core.

### Protocol translator example

 * Initial example implementation of simulated devices and protocol translator API use.

### Known issues

 * Starting edge-core may crash in some certain timing situations with `SIGSEGV`.
 * `POST` (CoAP) / `EXECUTE` (LWM2M) operation not supported.
 * `DELETE` (CoAP/LWM2M) operation not supported.
 * Devices moving between Mbed Edge instances have corner cases that are not supported.
 * Device unregistration to Mbed Cloud uses only expiration mechanism currently.
 * Mbed Cloud Core does not have hook point to add Mbed Cloud Core specific objects with resources.
 * Notifications from protocol translated resource value changes are currently forwarded only as Mbed Edge value changes and not as connected device value changes.
 * Protocol translated device registration to Core initiates full registration message to Mbed Cloud. This causes current subscriptions to be dropped to for Mbed Edge and protocol translated resources. Application logic must listen to registration notifications and renew subscriptions.
 * Registration update from Core to Mbed Cloud is not supported.
