/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#ifndef PT_API_VERSION
#define PT_API_VERSION 2
#endif
#if PT_API_VERSION != 2
#error "Including mixed versions of Protocol API"
#endif

#ifndef PT_API_H_
#define PT_API_H_

/**
 * \defgroup EDGE_PT_API_V2 Protocol translator API V2
 * @{
 */

#include <stdbool.h>

#include "pt-client-2/pt_common_api.h"
#include "pt-client-2/pt_client_api.h"
#include "pt-client-2/pt_userdata_api.h"
#include "pt-client-2/pt_devices_api.h"

/**
 * \file pt-client-2/pt_api.h
 * \brief Protocol translator external API V2.
 *
 * The protocol translator is used for bridging the non-LwM2M endpoint devices with the help of Device Management Edge
 * to Device Management.
 *
 * The protocol translator client start function is defined in this header. It is the main entry point
 * to initiate the communication between the protocol translator and Device Management Edge. It starts up the
 * event loop and keeps it running. The `pt_client_start()` function does not return until the event loop is
 * shut down.
 *
 * The API functions define the success and failure callback handlers that are called from an internal event
 * loop. Therefore, make sure that the operations in the callbacks do not block the event loop. All API functions
 * must have the `connection_id` as first argument. This specifies the connection to write the requests. Callbacks will
 * have a `userdata` argument, which is the user data that the application set in the protocol translator API calls.
 * Blocking the event loop blocks the protocol translator and it cannot continue until the control is given back to the
 * event loop from the customer callbacks. If there is a long running operation for the responses in the callback
 * handlers, you should move that into another thread.
 *
 * An example of registering the protocol translator with the customer callbacks:
 *
 * ~~~
 * #include <stdio.h>
 * #include "pt-client-2/pt_api.h"
 *
 * struct user_context {
 *     char *data;
 * };
 *
 * void connection_ready_handler(connection_id_t connection_id, const char *name, void *userdata)
 * {
 *     struct user_context *user_context = (struct user_context *) userdata;
 *     printf("Connection between protocol translator and Core service ready ('%s').\n", user_context->data);
 * }
 *
 * void protocol_translator_register_success(void *userdata)
 * {
 *     struct user_context *user_context = (struct user_context *) userdata;
 *     printf("Protocol translator registration success ('%s').\n", user_context->data);
 * }
 *
 * void protocol_translator_register_failed(void *userdata)
 * {
 *     struct user_context *user_context = (struct user_context *) userdata;
 *     printf("Protocol translator registration failed ('%s').\n", user_context->data);
 * }
 *
 * void shutdown_cb_handler(connection_id_t connection_id, void *userdata)
 * {
 *     struct user_context *user_context = (struct user_context *) userdata;
 *     printf("Received shutdown from the Edge Core, closing down ('%s').\n", user_context->data);
 *     // ... some data processing with the connection and devices ...
 * }
 *
 * void disconnected_handler(connection_id_t connection_id, void *userdata)
 * {
 *     struct user_context *user_context = (struct user_context *) userdata;
 *     printf("Disconnected from Edge Core ('%s').\n", user_context->data);
 *     // ... some data processing with the connection and devices ...
 * }
 *
 * int main(int argc, char **argv)
 * {
 *     if (argc != 2) {
 *         fprintf(stderr, "Usage: pt-client <protocol translator name>\n");
 *         return 1;
 *     }
 *
 *     // Initialize the protocol translator API.
 *     pt_api_init();
 *
 *     protocol_translator_callbacks_t pt_cbs;
 *     pt_cbs.connection_ready_cb = connection_ready_handler;
 *     pt_cbs.disconnected_cb = disconnected_handler;
 *     pt_cbs.connection_shutdown_cb = shutdown_cb_handler;
 *
 *     char *name = argv[1];
 *
 *     struct user_context user_context;
 *     user_context.data = "example-userdata";
 *
 *     pt_client_t *client;
 *     client = pt_client_create("/tmp/edge.sock", &pt_cbs);
 *
 *     pt_client_start(client,
 *                     protocol_translator_register_success,
 *                     protocol_translator_register_failed,
 *                     name,
 *                     &user_context);
 *
 *     pt_client_free(client);
 *     return 0;
 * }
 * ~~~
 *
 * Refer to `pt-example/client_example.c` in the https://github.com/ARMMbed/mbed-edge-examples repository for the
 * example use of full protocol translator API.
 */

/**
 * \brief Callback function prototype for the device resource specific action on #OPERATION_WRITE or #OPERATION_EXECUTE.
 *
 * Note the value size for integers and floats which are received from Device Management Edge.
 * This differs from the case when the protocol translator writes the value to Device Management Edge,
 * where it is allowed to write different size binary values. When the write is coming from
 * Device Management to Device Management Edge the value representation is `text-format`. Device Management Client
 * does not store the original binary value and the original value size is lost. The interpretation
 * of the value must be implemented in the callback function.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID targetted for this callback.
 * \param[in] object_id The object ID targetted.
 * \param[in] object_instance_id The object instance ID targetted.
 * \param[in] resource_id The resource ID targetted.
 * \param[in] operation The operation, for example OPERATION_WRITE.
 * \param[in] value A pointer to the value buffer.\n
 *            The ownership of the value buffer is within the `pt_resource_t` and the pointer is only valid for the
 *            duration of the function call.
 *            For different LwM2M data types there are byte-order restrictions as follows:\n
 *            \li \b String: UTF-8.
 *            \li \b Integer: A binary signed integer in network byte-order (64 bits).
 *            \li \b Float: IEEE 754-2008 floating point value in network byte-order (64 bits).
 *            \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *            \li \b Opaque: The sequence of binary data.
 *            \li \b Time: Same representation as integer.
 *            \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 * second is the Object Instance ID.\n Refer to: OMA Lightweight Machine to Machine Technical Specification for data
 * type specifications.
 * \param[in] size The size of the value to write.
 * \param[in] userdata The user-supplied context.
 *
 * \return Result of the resource callback function, should return `PT_STATUS_SUCCESS` when the operation was
 * successful, see ::pt_status_t for possible error codes.
 */
typedef pt_status_t (*pt_resource_callback)(const connection_id_t connection_id,
                                            const char *device_id,
                                            const uint16_t object_id,
                                            const uint16_t object_instance_id,
                                            const uint16_t resource_id,
                                            const uint8_t operation,
                                            const uint8_t *value,
                                            const uint32_t size,
                                            void *userdata);

/**
 * \brief Callback function prototype for freeing the resource value.
 *
 * \param[in] value Resource value to free.
 */
typedef void (*pt_resource_value_free_callback)(void *value);

/**
 * \brief A function pointer type definition for callbacks given in the device API functions as an argument.
 * This function definition is used for providing success and failure callback handlers.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback is running a long process, you need to move it to a worker thread.
 * If the process runs directly in the callback, it blocks the event loop, and thus the whole protocol translator.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID in context given as an argument.
 * \param[in] userdata The user-supplied context given as an argument in the protocol translator API function calls.
 */
typedef void (*pt_device_response_handler)(const connection_id_t connection_id, const char *device_id, void *userdata);

/**
 * \brief Creates the device structure.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The unique device identifier.
 * \param[in] lifetime The expected lifetime for the device. The device
 *                     registrations must be updated. This parameter is reserved and currently not used.
 *                     The translated endpoints are tracked withing the parent Edge device lifetime.
 * \param[in] queuemode The queue mode before the time is elapsed. This parameter is reserved, but currently not used.
 * \param[in] userdata The user data to add to the `pt_device_t` structure. Create this structure with
 *                     `pt_api_create_device_userdata()`.
 *
 * \return `PT_STATUS_SUCCESS` in case of success. Other error codes for failure.
 * Note! In case of an error where the status parameter returns something else than `PT_STATUS_SUCCESS`
 * the userdata free function will NOT be called and the userdata should be freed by the user.
 */
pt_status_t pt_device_create_with_userdata(const connection_id_t connection_id,
                                    const char *device_id,
                                    const uint32_t lifetime,
                                    const queuemode_t queuemode,
                                    pt_userdata_t *userdata);

/**
 * \brief Creates the device structure and enables additional features.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The unique device identifier.
 * \param[in] lifetime The expected lifetime for the device. The device
 *                     registrations must be updated. This parameter is reserved and currently not used.
 *                     The translated endpoints are tracked withing the parent Edge device lifetime.
 * \param[in] queuemode The queue mode before the time is elapsed. This parameter is reserved, but currently not used.
 * \param[in] features The feature flags for enabling features this device supports. See `pt_device_feature_e` enum
 *                     in `pt_common_api.h` for supported feature flags.
 * \param[in] userdata The user data to add to the `pt_device_t` structure. Create this structure with
 *                     `pt_api_create_device_userdata()`.
 *
 * \return `PT_STATUS_SUCCESS` in case of success. Other error codes for failure.
 * Note! In case of an error where the status parameter returns something else than `PT_STATUS_SUCCESS`
 * the userdata free function will NOT be called and the userdata should be freed by the user.
 */
pt_status_t pt_device_create_with_feature_flags(const connection_id_t connection_id,
                                                const char *device_id,
                                                const uint32_t lifetime,
                                                const queuemode_t queuemode,
                                                const uint32_t features,
                                                pt_userdata_t *userdata);

/**
 * \brief Creates the device structure.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The unique device identifier.
 * \param[in] lifetime The expected lifetime for the device. The device
 *                     registrations must be updated. This parameter is reserved and currently not used.
 *                     The translated endpoints are tracked withing the parent Edge device lifetime.
 * \param[in] queuemode The queue mode before the time is elapsed. This parameter is reserved, but currently not used.
 *
 * \return `PT_STATUS_SUCCESS` in case of success. Other error codes for failure.
 */
pt_status_t pt_device_create(const connection_id_t connection_id,
                             const char *device_id,
                             const uint32_t lifetime,
                             const queuemode_t queuemode);

/**
 * \brief Retrieves the feature flags of a device.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The unique device identifier.
 * \param[out] features Pointer to a uint32_t variable, On success it will contain the feature flags.
 *                      On failure the value will be undefined. See `pt_device_feature_e` enum
 *                      in `pt_common_api.h` for supported feature flags.
 *
 * \return `PT_STATUS_SUCCESS` in case of success. Other error codes for failure.
 */
pt_status_t pt_device_get_feature_flags(const connection_id_t connection_id,
                                        const char *device_id,
                                        uint32_t *features);

/**
 * \brief Endpoint device registration function. Every endpoint device must be registered with the protocol
 * translator and Device Management Edge before reading and writing device values.
 *
 * \param[in] connection_id The connection ID of the requesting application.
 * \param[in] device_id The device ID of the device to register.
 * \param[in] success_handler A function pointer that gets called when the device registration is successful.
 * \param[in] failure_handler A function pointer that gets called when the device registration fails.
 * \param[in] userdata The user-supplied context given as an argument to success and failure handler
 *                     functions.
 *
 * \return The status of the device registration operation.\n
 *         `PT_STATUS_SUCCESS` on successful registration.\n
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_device_register(const connection_id_t connection_id,
                               const char *device_id,
                               pt_device_response_handler success_handler,
                               pt_device_response_handler failure_handler,
                               void *userdata);

/**
 * \brief Endpoint device unregistration function. If the device unregistration succeeds, the device instance
 *        data will be freed from memory.
 *
 * \param[in] connection_id The connection ID of the requesting application.
 * \param[in] device_id The device ID of the device to unregister.
 * \param[in] success_handler A function pointer that gets called when the device unregistration is successful.
 * \param[in] failure_handler A function pointer that gets called when the device unregistration fails.
 * \param[in] userdata The user-supplied context given as an argument to success and failure handler
 *                     functions.
 *
 * \return The status of the device unregistration operation.\n
 *         `PT_STATUS_SUCCESS` on successful unregistration.\n
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_device_unregister(const connection_id_t connection_id,
                                 const char *device_id,
                                 pt_device_response_handler success_handler,
                                 pt_device_response_handler failure_handler,
                                 void *userdata);

/**
 * \brief Writes changed values from the endpoint device to Edge Core.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device from which to write the value to Edge Core.
 * \param[in] success_handler A function pointer to be called when the value was written successfully.
 * \param[in] failure_handler A function pointer to be called when the writing fails.
 * \param[in] userdata The user-supplied context given as an argument to the success and failure handler
 *                     functions.
 *
 * \return The status of the write value operation.\n
 *         `PT_STATUS_SUCCESS` on successful write.\n
 *         See ::pt_status_t for possible error codes.
 *         Note: doesn't call the callbacks if PT_STATUS_INVALID_PARAMETERS or PT_STATUS_NOT_CONNECTED is returned.
 */
pt_status_t pt_device_write_values(const connection_id_t connection_id,
                                   const char *device_id,
                                   pt_device_response_handler success_handler,
                                   pt_device_response_handler failure_handler,
                                   void *userdata);

/**
 * \brief Set a new value to resource in the device.
 *
 * This function does not update the value to Edge Core. Call `pt_device_write_values()` to initiate messaging to
 * Edge Core. This function can called multiple times for the device before updating the value to Edge Core.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID targetted for the write.
 * \param[in] object_id The object ID targetted.
 * \param[in] object_instance_id The object instance ID targetted.
 * \param[in] resource_id The resource ID targetted.
 * \param[in] value The value to write to the resource.
 * \param[in] value_len The size of the value to write.
 * \param[in] value_free_cb A callback function to free the value buffer that will be called when the resource is
 *                          destroyed or a new value buffer is assigned.
 *
 * \return `PT_STATUS_SUCCESS` in case of success. Other error codes for failure.
 *         Note! If this function returns any error, the `value_free_cb` will be called to avoid a memory leak.
 */
pt_status_t pt_device_set_resource_value(const connection_id_t connection_id,
                                         const char *device_id,
                                         const uint16_t object_id,
                                         const uint16_t object_instance_id,
                                         const uint16_t resource_id,
                                         const uint8_t *value,
                                         uint32_t value_len,
                                         pt_resource_value_free_callback value_free_cb);

/**
 * \brief Utility function to check if device already exists for the connection.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 *
 * \return True if device is found. False if not.
 */
bool pt_device_exists(const connection_id_t connection_id, const char *device_id);

/**
 * \brief Utility function to check if resource already exists for the connection and device.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 * \param[in] object_id The object ID to find.
 * \param[in] object_instance_id The object instance ID to find.
 * \param[in] resource_id The resource ID to find.
 *
 * \return True if resource is found. False if not.
 */
bool pt_device_resource_exists(const connection_id_t connection_id,
                               const char *device_id,
                               const uint16_t object_id,
                               const uint16_t object_instance_id,
                               const uint16_t resource_id);

/**
 * \brief Adds a read-only resource to a device.
 *
 * This function does not set any callbacks to the created resource. The created resource
 * functions only as a read-only resource from the Pelion Cloud perspective.
 * The value can be updated directly from the wrapping application. The read-only restriction
 * applies only to requests coming from Pelion Cloud. The protocol translator application may
 * write new values to the resource with `pt_device_set_resource_value()' function and in the
 * end update the set value by calling `pt_device_write_values()` function.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to which to add the resource.
 * \param[in] object_id The object ID to which to add the resource.
 * \param[in] object_instance_id The object instance ID to which to add the resource.
 * \param[in] resource_id The resource ID for the added resource.
 * \param[in] type The resource type.
 * \param[in] value A pointer to the value buffer.
 *            The ownership of the value buffer is within the `pt_client_t`.
 *            When the resource is destroyed or a new value buffer is set by calling `pt_device_set_resource_value()`
 *            the `value_free_cb()` is called with the old value buffer as parameter.\n
 *            For different LwM2M data types there are byte-order restrictions as follows:\n
 *            \li \b String: UTF-8.
 *            \li \b Integer: A binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *            \li \b Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *            \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *            \li \b Opaque: The sequence of binary data.
 *            \li \b Time: Same representation as integer.
 *            \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 *                       second is the Object Instance ID.\n
 *            Refer to: OMA Lightweight Machine to Machine Technical Specification for data type specifications.
 * \param[in] value_size The size of the value buffer.
 * \param[in] value_free_cb A callback function to free the value buffer that will be called when the resource is
 *                          destroyed or a new value buffer is assigned.
 *
 * \return `PT_STATUS_SUCCESS` on successful resource create.\n
 *         See ::pt_status_t for possible error codes.
 *         Note: if there is an error, it will call the `value_free_cb()` to avoid a memory leak.
 *
 */
pt_status_t pt_device_add_resource(const connection_id_t connection_id,
                                   const char *device_id,
                                   const uint16_t object_id,
                                   const uint16_t object_instance_id,
                                   const uint16_t resource_id,
                                   const Lwm2mResourceType type,
                                   uint8_t *value,
                                   uint32_t value_size,
                                   pt_resource_value_free_callback value_free_cb);

/**
 * \brief Adds a resource to a device with a callback.
 *
 * This function creates a resource with allowed operations specified by \p operations.
 * The callback is set for the write and execute actions and are triggered when
 * corresponding requests are received from Device Management.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to which to add the resource.
 * \param[in] object_id The object ID to which to add the resource.
 * \param[in] object_instance_id The object instance ID to which to add the resource.
 * \param[in] resource_id The resource ID for the added resource.
 * \param[in] type The resource type.
 * \param[in] operations The operations this resource will allow.\n
 *                       For example, GET/#OPERATION_READ and PUT/#OPERATION_WRITE. The value is a bit field of
 *                       allowed operations.\n
 *                       \li If #OPERATION_WRITE is set to flags, the parameter for \p callback must be populated.
 *                       \li If #OPERATION_EXECUTE is set to flags, the parameter for \p callback must be populated.\n
 *                       Now, you can have a combination of #OPERATION_EXECUTE and #OPERATION_WRITE for the resource.
 *
 * \note Note the difference when writing a value from the protocol translator to Device Management Edge opposed
 * to receiving a write from Device Management Edge. It is allowed to write different sized binary
 * integers and float towards Device Management Edge. On the other hand, when receiving a write from
 * Device Management Edge, the integer or float value is always 64 bit.
 *
 * \param[in] value The pointer to value buffer.
 *            The ownership of the value buffer is within the `pt_resource_t`.
 *            When the resource is destroyed or a new value buffer is set by calling `pt_device_set_resource_value()`
 *            the `value_free_cb` is called with the old value buffer as parameter.\n
 *            For different LwM2M data types there are byte-order restrictions as follows:\n
 *            \li \b String: UTF-8
 *            \li \b Integer: A binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *            \li \b Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *            \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *            \li \b Opaque: The sequence of binary data.
 *            \li \b Time: Same representation as integer.
 *            \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 *                           second is the Object Instance ID.\n
 *            Refer to: OMA Lightweight Machine to Machine Technical Specification for data type specifications.
 * \param[in] value_size The size of the value buffer.
 * \param[in] value_free_cb A callback function to free the value buffer that will be called when the resource is
 *                          destroyed or a new value buffer is assigned.
 * \param[in] callback Optional callback for this resource. The callback can be given when
 *                     the resource has #OPERATION_WRITE and/or #OPERATION_EXECUTE set to allowed operations.
 *
 * \return `PT_STATUS_SUCCESS` on successful resource create.\n
 *         See ::pt_status_t for possible error codes.
 *         Note: if there is an error, it will call the `value_free_cb()` to avoid a memory leak.
 *
 */
pt_status_t pt_device_add_resource_with_callback(const connection_id_t connection_id,
                                                 const char *device_id,
                                                 const uint16_t object_id,
                                                 const uint16_t object_instance_id,
                                                 const uint16_t resource_id,
                                                 const Lwm2mResourceType type,
                                                 const uint8_t operations,
                                                 uint8_t *value,
                                                 uint32_t value_size,
                                                 pt_resource_value_free_callback value_free_cb,
                                                 pt_resource_callback callback);

/**
 * \brief Utility function to get the current value in a resource.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID of device to get the resource value.
 * \param[in] object_id The object ID of the object which resource value to get.
 * \param[in] object_instance_id The object instance ID of the object instance which resource value to get.
 * \param[in] resource_id The resource ID of the resource which value to get.
 * \param[out] value_out On success it's updated to point at the value of the resource.
 * \param[out] value_len_out On success it returns the size of the resource.
 *
 * \return `PT_STATUS_SUCCESS` in on success. Other error codes on failure.
 */
pt_status_t pt_device_get_resource_value(connection_id_t connection_id,
                                         const char *device_id,
                                         const uint16_t object_id,
                                         const uint16_t object_instance_id,
                                         const uint16_t resource_id,
                                         uint8_t **value_out,
                                         uint32_t *value_len_out);

/**
 * \brief Get the id of first free object instance for given object.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID of the device.
 * \param[in] object_id The object ID of which next free object instance ID got.
 *
 * \return Return the object instance id of the first free object instance in object. Returns -1 if the connection or
 *         device does not exist, if the object doesn't exist 0 is returned as that would be the first free object
 *         instance if the object was created.
 */
int32_t pt_device_get_next_free_object_instance_id(connection_id_t connection_id,
                                                   const char *device_id,
                                                   uint16_t object_id);

/**
 * \brief Retrieve the set user data in the device.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 *
 * \return Pointer to the user data structure. If there's no such device or no user data for the existing device, a NULL
 *         is returned.
 */
pt_userdata_t *pt_device_get_userdata(connection_id_t connection_id, const char *device_id);

/**
 * \brief Retrieve the set user data in the resource. Client needs to provide the full path to the resource.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 * \param[in] object_id The object ID to find.
 * \param[in] object_instance_id The object instance ID to find.
 * \param[in] resource_id The resource ID to find.
 *
 * \return Pointer to the user data structure. If there's no such resource or no user data for the existing resource,
 *         a NULL is returned.
 */
pt_userdata_t *pt_resource_get_userdata(connection_id_t connection_id,
                                        const char *device_id,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id);

/**
 * \brief Set the set user data to the device. This may be useful if the client needs to associate some extra data with
 *        the device. Create the userdata using the API function `pt_api_create_userdata()`.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 * \param[in] userdata Pointer to the user data structure.
 *
 * \return `PT_STATUS_SUCCESS` if the device was found and the userdata was set successfully.
 *         Other error codes if setting userdata fails.
 */
pt_status_t pt_device_set_userdata(connection_id_t connection_id, const char *device_id, pt_userdata_t *userdata);

/**
 * \brief Set the set user data to the resource. This may be useful if the client needs to associate some extra data
 *        with the device. Create the userdata using the API function `pt_api_create_userdata()`.
 *        Client needs to provide the full path to the resource.
 *
 * \param[in] connection_id The ID of the connection of the requesting application.
 * \param[in] device_id The device ID to find.
 * \param[in] object_id The object ID to find.
 * \param[in] object_instance_id The object instance ID to find.
 * \param[in] resource_id The resource ID to find.
 * \param[in] userdata Pointer to the user data structure.
 *
 * \return `PT_STATUS_SUCCESS` if the resource was found and the userdata was set successfully.
 *         Other error codes if setting userdata fails.
 */
pt_status_t pt_resource_set_userdata(connection_id_t connection_id,
                                     const char *device_id,
                                     const uint16_t object_id,
                                     const uint16_t object_instance_id,
                                     const uint16_t resource_id,
                                     pt_userdata_t *userdata);

/**
 * @}
 * Close EDGE_PT_API_V2 Doxygen group definition
 */

#endif /* PT_API_H_ */
