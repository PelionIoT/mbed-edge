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
#define PT_API_VERSION 1
#endif
#if PT_API_VERSION != 1
#error "Including mixed versions of Protocol API"
#endif

#ifndef PT_API_H_
#define PT_API_H_

#ifdef __GNUC__
#define DEPRECATED(func) func __attribute__((deprecated))
#else
#pragma message("WARNING: Implement DEPRECATED macro, it is missing.")
#define DEPRECATED(func) func
#endif

#include "ns_list.h"

#include "common/constants.h"
#include "common/default_message_id_generator.h"
#include "edge-rpc/rpc.h"

/**
 * \defgroup EDGE_PT_API Protocol translator API v1
 * \brief The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 * @{
 */

/**
 * \file pt-client/pt_api.h
 * \brief <b>**Deprecated**</b> Protocol translator client for API v1.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * The protocol translator is used for bridging the non-LwM2M endpoint devices with the help of Edge
 * to Pelion Cloud.
 *
 * The protocol translator client start function is defined in this header. It is the main entry point
 * to initiate the communication between the protocol translator and Edge. It starts up the
 * event loop and keeps it running. The `pt_client_start()` function does not return until the event loop is
 * shut down.
 * ~~~
 * #include <stdio.h>
 * #include <stdint.h>
 * #include "pt-client/pt_api.h"
 *
 * void connection_ready_handler(connection_t *connection, void *userdata)
 * {
 *     printf("Connection between protocol translator and Core service ready.\n");
 * }
 *
 * int received_write_handler(connection_t *connection,
 *                            const char *device_id, const uint16_t object_id,
 *                            const uint16_t instance_id,
 *                            const uint16_t resource_id,
 *                            const unsigned int operation,
 *                            const uint8_t *value, const uint32_t value_size,
 *                            void *userdata)
 * {
 *     printf("Received write from the Edge Core.\n");
 * }
 *
 * void shutdown_cb_handler(connection_t **connection, void* userdata)
 * {
 *     printf("Received shutdown from the Edge Core, closing down.\n");
 * }
 *
 * int main(int argc, char **argv)
 * {
 *     if (argc != 3) {
 *         fprintf(stderr, "Usage: pt-client <protocol translator name>\n");
 *         return 1;
 *     }
 *
 *     connection_t *connection = NULL;
 *     protocol_translator_callbacks_t pt_cbs;
 *     pt_cbs.connection_ready_cb = connection_ready_handler;
 *     pt_cbs.received_write_cb = received_write_handler;
 *     pt_cbs.connection_shutdown_cb = shutdown_cb_handler;
 *     char *name = argv[1];
 *     void *userdata = (void*) "example_userdata";
 *     pt_client_start('/tmp/edge.sock', name, &pt_cbs, userdata, connection);
 *
 *     return 0;
 * }
 * ~~~
 *
 * The API functions define the success and failure callback handlers that are called from an internal event
 * loop. Therefore, make sure that the operations in the callbacks do not block the event loop. All API functions
 * must have the `connection` as first argument. This is the connection to write the requests. Callbacks will have
 * an `userdata` argument, which is the application user data set in the protocol translator API calls.
 * Blocking the event loop blocks the protocol translator and it cannot continue until the control is given back to
 * the event loop from customer callbacks. If there is a long running operation for the responses in the callback
 * handlers, you should move that into a thread.
 *
 * An example of registering the protocol translator with the customer callbacks:
 * ~~~
 *
 * struct user_context
 * {
 *   char *data;
 * };
 *
 * static void registration_success(void *userdata)
 * {
 *    printf("Protocol translator registration successful.\n");
 *    struct user_context *user_context = (struct user_context*) userdata;
 *    // work with the user_context->data
 * }
 *
 * static void registration_failure(void *userdata)
 * {
 *   printf("Protocol translator registration failed.\n");
 *   struct user_context *user_context = (struct user_context*) userdata;
 *   free(user_context->data);
 *   free(user_context);
 * }
 *
 * static void device_registered_successfully(const char* device_id, void *userdata)
 * {
 *    //device_id would be 'test-device'
 *    // work with the userdata
 * }
 *
 * static void device_register_failed(const char* device_id, void *userdata)
 * {
 *    //device_id would be 'test-device'
 *    // work with the userdata
 * }
 *
 * struct user_context *user_context = malloc(sizeof(struct user_context));
 * user_context->data = "Data...";
 * pt_register_protocol_translator(connection, registration_success, registration_failure, user_context);
 *
 * pt_device_t device = pt_create_device(strdup("test-device")...);
 *
 * pt_register_device(connection, device, device_registered_successfully,
 *      device_register_failed, user_context);
 *
 * ~~~
 *
 * Refer to `pt-client/client_example.c` for the example use of full protocol translator API.
 */

typedef struct pt_resource pt_resource_t;
typedef struct pt_resource pt_resource_opaque_t;
typedef struct pt_object_instance pt_object_instance_t;
typedef struct pt_object pt_object_t;
typedef struct pt_device pt_device_t;

/**
 * \brief Callback function prototype for the device resource specific action on #OPERATION_WRITE or #OPERATION_EXECUTE.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * Note the value size for integers and floats which are received from Edge Core.
 * This differs from the case when the protocol translator writes the value to Edge Core
 * where it is allowed to write different size binary values. When the write is coming from
 * Device Management to Edge Core the value representation is `text-format`. Device Management Client
 * does not store the original binary value and the original value size is lost. The interpretation
 * of the value must be implemented in the callback function.
 *
 * \param resource The resource that the action was triggered on.
 * \param value A pointer to the value buffer.\n
 *        The ownership of the value buffer is within the `pt_resource_t`.
 *        For different LwM2M data types there are byte-order restrictions as follows:\n
 *        \li \b String: UTF-8.
 *        \li \b Integer: A binary signed integer in network byte-order (64 bits).
 *        \li \b Float: IEEE 754-2008 floating point value in network byte-order (64 bits).
 *        \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *        \li \b Opaque: The sequence of binary data.
 *        \li \b Time: Same representation as integer.
 *        \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 * second is the Object Instance ID.\n Refer to: OMA Lightweight Machine to Machine Technical Specification for data
 * type specifications. \param size The size of the value to write. \param userdata The user-supplied context.
 */
DEPRECATED(
    typedef void (*pt_resource_callback)(const pt_resource_t *resource,
                                         const uint8_t *value,
                                         const uint32_t size,
                                         void *userdata));

/**
 * \brief A function prototype for calling the client code when the connection is ready for passing messages
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection which is ready.
 * \param userdata The user supplied data to pass back when the handler is called.
 */
DEPRECATED(typedef void (*pt_connection_ready_cb)(struct connection *connection, void *userdata));

/**
 * \brief A function prototype for calling the client code when the connection is disconnected.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection which disconnected.
 * \param userdata The user supplied data to pass back the the handler is called.
 */
DEPRECATED(typedef void (*pt_disconnected_cb)(struct connection *connection, void *userdata));

/**
 * \brief A function prototype for calling the client code when the connection is shutting down
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection reference of the protocol translator client connection.
 * \param userdata The user supplied data to pass back when the handler is called.
 */
DEPRECATED(typedef void (*pt_connection_shutdown_cb)(struct connection **connection, void *userdata));

/**
 * \brief Function pointer type definition for handling received message from Edge Core.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.\n
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread.\n
 * If the processing is run directly in the callback it will block the event loop and therefore it
 * will block the whole protocol translator.
 *
 * \param connection The connection which this write originates.
 * \param device_id The device ID to write the data.
 * \param object_id The object ID to write the data.
 * \param instance_id The instance ID to write the data.
 * \param resource_id The resource ID to write the data.
 * \param operation The operation of the write.
 * \param value The pointer to byte data to write.
 * \param value_size The length of the data.
 * \param userdata The pointer to user supplied data from `pt_client_start`.
 *
 * \return Returns 0 on success and non-zero on failure.
 */
DEPRECATED(
    typedef int (*pt_received_write_handler)(struct connection *connection,
                                             const char *device_id, const uint16_t object_id,
                                             const uint16_t instance_id,
                                             const uint16_t resource_id,
                                             const unsigned int operation,
                                             const uint8_t *value, const uint32_t value_size,
                                             void *userdata));

typedef enum {
    NONE,
    QUEUE
} queuemode_t;

typedef enum {
    PT_STATUS_SUCCESS = 0,
    PT_STATUS_ERROR,
    PT_STATUS_ITEM_EXISTS,
    PT_STATUS_INVALID_PARAMETERS,
    PT_STATUS_ALLOCATION_FAIL,
    PT_STATUS_NOT_CONNECTED
} pt_status_t;

typedef struct pt_resource {
    ns_list_link_t link;
    pt_object_instance_t *parent;
    Lwm2mResourceType type;
    uint16_t id;
    unsigned int operations;
    uint8_t *value;
    uint32_t value_size;
    pt_resource_callback callback;
} pt_resource_t;

typedef NS_LIST_HEAD(pt_resource_t, link) pt_resource_list_t;

typedef struct pt_object_instance {
    ns_list_link_t link;
    pt_object_t *parent;
    pt_resource_list_t *resources;
    uint16_t id;
} pt_object_instance_t;

typedef NS_LIST_HEAD(pt_object_instance_t, link) pt_object_instance_list_t;

typedef struct pt_object {
    ns_list_link_t link;
    pt_device_t *parent;
    pt_object_instance_list_t *instances;
    uint16_t id;
} pt_object_t;

typedef NS_LIST_HEAD(pt_object_t, link) pt_object_list_t;

struct pt_device_userdata_s;

typedef void (*pt_device_free_userdata_cb_t)(void *data);

/**
 * \brief Contains fields for client user data.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * If the client wants to associate data with the device, this structure may be used.
 * Create this structure using pt_api_create_device_userdata.
 * The PT API will deallocate this structure and call the pt_device_free_userdata call-back when the pt_device_t
 * structure is destroyed. However the client is responsible to free the pt_device_userdata_t#data using the
 * pt_device_userdata_t#pt_device_free_userdata call-back or in some other way.
 */
typedef struct pt_device_userdata_s {
    void *data; /**< Pointer to client's data that may be associated with the device. */
    pt_device_free_userdata_cb_t
            pt_device_free_userdata; /**< Points to customer implementation to free the userdata. */
} pt_device_userdata_t;

typedef struct pt_device {
    ns_list_link_t link;
    char* device_id;
    uint32_t lifetime;
    queuemode_t queuemode;
    pt_device_userdata_t *userdata;
    pt_object_list_t *objects;
} pt_device_t;

typedef struct client_data_s {
    char* name;
    bool registered;
    int id;
    void* method_table;
} client_data_t;

/**
 * \brief A structure to hold the callbacks of the protocol translator
 */
typedef struct protocol_translator_callbacks {
    pt_connection_ready_cb connection_ready_cb;
    pt_disconnected_cb disconnected_cb;
    pt_received_write_handler received_write_cb; /**< Applies only to deprecated API v1. Removed in API v2. */
    pt_connection_shutdown_cb connection_shutdown_cb;
} protocol_translator_callbacks_t;

typedef struct connection connection_t;

/**
 * \brief A function pointer type definition for callbacks given in the protocol translator API functions as an argument.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * This function definition is used for providing success and failure callback handlers.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback is running a long process, you need to move it to a worker thread.
 * If the process runs directly in the callback, it blocks the event loop, and thus the whole protocol translator.
 *
 * \param userdata The user-supplied context given as an argument in the protocol translator
 * API functions.
 */
DEPRECATED(typedef void (*pt_response_handler)(void* userdata));

/**
 * \brief A function pointer type definition for callbacks given in the device API functions as an argument.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * This function definition is used for providing success and failure callback handlers.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback is running a long process, you need to move it to a worker thread.
 * If the process runs directly in the callback, it blocks the event loop, and thus the whole protocol translator.
 *
 * \param device_id The device ID in context given as an argument.
 * \param userdata The user-supplied context given as an argument in the protocol translator
 * API functions.
 */
DEPRECATED(typedef void (*pt_device_response_handler)(const char* device_id, void* userdata));

/**
 * \brief Protocol translator registration function. Every protocol translator must register itself
 * with Edge before starting to handle endpoint related functions.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection of the requesting application.
 * \param success_handler A function pointer to be called when the protocol translator registration
 * is successful.
 * \param failure_handler A function pointer to be called when the protocol translator registration
 * fails.
 * \param userdata The user-supplied context given as an argument to success and failure handler
 * functions.
 * \return The status of the protocol translator registration operation.\n
 *         `PT_STATUS_SUCCESS` on successful registration.\n
 *         See ::pt_status_t for possible error codes.
 */
DEPRECATED(
    pt_status_t pt_register_protocol_translator(connection_t *connection,
                                                pt_response_handler success_handler,
                                                pt_response_handler failure_handler,
                                                void* userdata));

/**
 * \brief Endpoint device registration function. Every endpoint device must be registered with the protocol
 * translator and Edge before reading and writing device values.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection of the requesting application.
 * \param device The structure containing structured information of the device to be registered.
 * \param success_handler A function pointer that gets called when the device registration is successful.
 * \param failure_handler A function pointer that gets called when the device registration fails.
 * \param userdata The user-supplied context given as an argument to success and failure handler
 * functions.
 * \return The status of the device registration operation.\n
 *         `PT_STATUS_SUCCESS` on successful registration.\n
 *         See ::pt_status_t for possible error codes.
 */
DEPRECATED(
    pt_status_t pt_register_device(connection_t *connection,
                                   pt_device_t *device,
                                   pt_device_response_handler success_handler,
                                   pt_device_response_handler failure_handler,
                                   void *userdata));

/**
 * \brief Endpoint device unregistration function.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection of the requesting application.
 * \param device The structure containing structured information of the device to be unregistered.
 * \param success_handler A function pointer that gets called when the device unregistration is successful.
 * \param failure_handler A function pointer that gets called when the device unregistration fails.
 * \param userdata The user-supplied context given as an argument to success and failure handler
 * functions.
 * \return The status of the device unregistration operation.\n
 *         `PT_STATUS_SUCCESS` on successful unregistration.\n
 *         See ::pt_status_t for possible error codes.
 */
DEPRECATED(
    pt_status_t pt_unregister_device(connection_t *connection,
                                     pt_device_t *device,
                                     pt_device_response_handler success_handler,
                                     pt_device_response_handler failure_handler,
                                     void *userdata));

/**
 * \brief Used to create the pt_device_userdata_s structure.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param data Pointer to client's data to associate with the device.
 * \param free_userdata_cb Pointer to function which will be called to free the data.
 *                         NULL value is allowed. In this case no user data free
 *                         function will be called. It's possible that there is no need
 *                         to deallocate the data.
 * \return pointer to `pt_device_userdata_t` if memory allocation succeeds.
 *         NULL if memory allocation fails. In this case calls `free_userdata_cb` immediately if applicable.
 */
DEPRECATED(pt_device_userdata_t *pt_api_create_device_userdata(void *data,
                                                               pt_device_free_userdata_cb_t free_userdata_cb));

/**
 * \brief Creates the device structure.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param device_id The unique device identifier. The ownership of the
 * `device_id` is transferred to returned `pt_device_t`
 * \param lifetime The expected lifetime for the device. The device
 * registrations must be updated. This parameter is reserved and currently not used.
 * The translated endpoints are tracked withing the parent Edge device lifetime.
 * \param queuemode The queue mode before the time is elapsed.
 * \param status A pointer to user provided variable for the operation status
 * output. If a device was created, the status will be set to `PT_STATUS_SUCCESS`.
 * \param userdata The user data to add to the `pt_device_t` structure. Create this structure with
 *                 `pt_api_create_device_userdata`.
 *                 Note! If memory allocation fails in this function, userdata free function call-back will be called
 *                 immediately.
 * \return The allocated structure.\n The caller will have the ownership of the reserved memory.
 */
DEPRECATED(
    pt_device_t *pt_create_device_with_userdata(char *device_id,
                                                const uint32_t lifetime,
                                                const queuemode_t queuemode,
                                                pt_status_t *status,
                                                pt_device_userdata_t *userdata));

/**
 * \brief Creates the device structure.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param device_id The unique device identifier. The ownership of the
 * `device_id` is transferred to returned `pt_device_t`
 * \param lifetime The expected lifetime for the device. The device
 * registrations must be updated. This parameter is reserved and currently not used.
 * The translated endpoints are tracked withing the parent Edge device lifetime.
 * \param queuemode The queue mode before the time is elapsed.
 * \param status A pointer to user provided variable for the operation status
 * output. If a device was created, the status will be set to `PT_STATUS_SUCCESS`.
 * \return The allocated structure.\n
 *         The caller will have the ownership of the reserved memory.
 */
DEPRECATED(
    pt_device_t *pt_create_device(char *device_id,
                                  const uint32_t lifetime,
                                  const queuemode_t queuemode,
                                  pt_status_t *status));

/**
 * \brief Deallocates the reserved memory for the device structure.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * The structure is iterated and all lists and reserved data structures are freed.
 *
 * \param pt_device The structure to deallocate for.
 */
DEPRECATED(void pt_device_free(pt_device_t *device));

/**
 * \brief Adds an object to a device.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param device The device to which the object list is added.
 * \param id The object ID of the added object.
 * \param status A pointer to user provided variable for the operation status output.\n
 *        If a device was created, the status is set to `PT_STATUS_SUCCESS`.
 * \return The added empty object.\n
 *         The ownership of the returned object is within the `pt_device_t`.
 */
DEPRECATED(pt_object_t *pt_device_add_object(pt_device_t *device, uint16_t id, pt_status_t *status));

/**
 * \brief Finds an object from the device.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param device The device object.
 * \param id The object ID to find from the device.
 * \return The found object pointer or NULL.\n
 *         The ownership of the object is within the `pt_device_t`
 */
DEPRECATED(pt_object_t *pt_device_find_object(pt_device_t *device, uint16_t id));

/**
 * \brief Adds an object instance to an object.
 * \deprecated The protocol translator API v1 is deprecated. The API will exists until end of 2019.
 *
 * \param object The object to which to add the object instance.
 * \param id The object instance ID of the added object instance.
 * \param status A pointer to user provided variable for the operation status output. If a device was created, the
 * status is set to `PT_STATUS_SUCCESS`. \return The added empty object instance.\n The ownership of the returned object
 * instance is within the `pt_object_t`.
 */
DEPRECATED(pt_object_instance_t * pt_object_add_object_instance(pt_object_t *object, uint16_t id, pt_status_t *status));

/**
 * \brief Finds an object instance from object
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param object The object.
 * \param id The object instance ID to find from the object.
 * \return The found object instance pointer or NULL.\n
 *         The ownership of the object instance is within the `pt_object_t`.
 */
DEPRECATED(pt_object_instance_t *pt_object_find_object_instance(pt_object_t *object, uint16_t id));

/**
 * \brief Adds a read-only resource to an object instance.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * This function does not set any callbacks to the created resource. The created resource
 * functions only as a read-only resource. The value can be updated directly from the
 * wrapping application. The read-only restriction applies only to requests coming from
 * Device Management.
 *
 * \param object_instance The object instance to which to add the resource.
 * \param id The resource ID for the added resource.
 * \param type The resource type.
 * \param value A pointer to the value buffer.
 *        The ownership of the value buffer is within the `pt_resource_t`.
 *        For different LwM2M data types there are byte-order restrictions as follows:\n
 *        \li \b String: UTF-8.
 *        \li \b Integer: A binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *        \li \b Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *        \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *        \li \b Opaque: The sequence of binary data.
 *        \li \b Time: Same representation as integer.
 *        \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID
 *        and the second is the Object Instance ID.\n
 *        Refer to: OMA Lightweight Machine to Machine Technical Specification for data type specifications.
 * \param value_size The size of the value buffer.
 * \param status A pointer to user provided variable for the operation status output. If a device was created, the
 * status is set to `PT_STATUS_SUCCESS`
 *
 * \return The added empty resource.\n
 *         The ownership of the returned resource is within the `pt_object_instance_t`.
 */
DEPRECATED(
    pt_resource_t *pt_object_instance_add_resource(pt_object_instance_t *object_instance,
                                                   uint16_t id,
                                                   Lwm2mResourceType type,
                                                   uint8_t *value,
                                                   uint32_t value_size,
                                                   pt_status_t *status));

/**
 * \brief Adds a resource to an object instance with callbacks.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * This function creates a resource with allowed operations specified by \p operations.
 * The callbacks are set for the read and execute actions and are triggered when
 * corresponding requests are received from Device Management.
 *
 * \param object_instance The object instance to which to add the resource.
 * \param id The resource ID of the added resource.
 * \param type The resource type.
 * \param operations The operations this resource will allow.\n
   For example, GET/#OPERATION_READ and PUT/#OPERATION_WRITE. The value is a bit field of allowed operations.\n
 * \li If #OPERATION_WRITE is set to flags, the parameter for \p callback must be populated.
 * \li If #OPERATION_EXECUTE is set to flags, the parameter for \p callback must be populated.\n
 * Now, you can have a combination of #OPERATION_EXECUTE and #OPERATION_WRITE for the resource.
 *
 * \note Note the difference when writing a value from the protocol translator to Edge Core opposed
 * to receiving a write from Edge Core. It is allowed to write different sized binary
 * integers and float towards Edge Core. On the other hand, when receiving a write from
 * Edge Core, the integer or float value is always 64 bit.
 *
 * \param value The pointer to value buffer.
 *        The ownership of the value buffer is within the `pt_resource_t`.
 *        For different LwM2M data types there are byte-order restrictions as follows:\n
 *        \li \b String: UTF-8
 *        \li \b Integer: A binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *        \li \b Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *        \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *        \li \b Opaque: The sequence of binary data.
 *        \li \b Time: Same representation as integer.
 *        \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 second is the Object Instance ID.\n
 *        Refer to: OMA Lightweight Machine to Machine Technical Specification for data type specifications.
 * \param value_size The size of the value buffer.
 * \param status A pointer to the user provided variable for the operation status output. If a device was created, the
 status
 * is set to `PT_STATUS_SUCCESS`
 * \param callback The callbacks for this resource. The callbacks can be given when
 * the resource has #OPERATION_WRITE and/or #OPERATION_EXECUTE set to allowed operations.
 *
 * \return The added empty resource.\n
 *         The ownership of the returned resource is within the `pt_object_instance_t`
 */
DEPRECATED(
    pt_resource_t *pt_object_instance_add_resource_with_callback(pt_object_instance_t *object_instance,
                                                                 uint16_t id,
                                                                 Lwm2mResourceType type,
                                                                 uint8_t operations,
                                                                 uint8_t *value,
                                                                 uint32_t value_size,
                                                                 pt_status_t *status,
                                                                 pt_resource_callback callback));

/**
 * \brief Finds a resource from an object instance.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param instance The object instance.
 * \param id The resource ID to find from the object instance.
 * \return The found resource pointer or NULL.\n
 *         The ownership of the resource is within the `pt_object_instance_t`.
 */
DEPRECATED(pt_resource_t *pt_object_instance_find_resource(pt_object_instance_t *instance, uint16_t id));

/**
 * \brief Writes the value from the endpoint device to Edge Core.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param connection The connection of the requesting application.
 * \param device The device from which to write the value to Edge Core.
 * \param objects The full object structure of the objects, object instances and resources to write.
 * \param success_handler A function pointer to be called when the value was written successfully.
 * \param failure_handler A function pointer to be called when the writing fails.
 * \param userdata The user-supplied context given as an argument to the success and failure handler
 * functions.
 * \return The status of the write value operation.\n
 *         `PT_STATUS_SUCCESS` on successful write.\n
 *         See ::pt_status_t for possible error codes.
 */
DEPRECATED(
    pt_status_t pt_write_value(connection_t *connection,
                               pt_device_t *device,
                               pt_object_list_t *objects,
                               pt_device_response_handler success_handler,
                               pt_device_response_handler failure_handler,
                               void *userdata));

/**
 * \brief The function to handle the received write calls from Edge Core.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param request The request object.
 * \param json_params The params object from JSON request.
 * \param result The output parameter to return the result of the function.
 * \param userdata The internal RPC supplied context.
 * \return 0 is returned for the successful handling of the write request.\n
 *         1 is returned for failure.
 */
DEPRECATED(int pt_receive_write_value(json_t *request, json_t *json_params, json_t **result, void *userdata));

/**
 * \brief Starts the protocol translator client event loop and tries to connect to a local instance
 * of Edge.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 *
 * \param socket_path The path to AF_UNIX domain socket to connect.
 * \param name The protocol translator name, must be unique in the Edge instance. The protocol translator API cleans the
 * reserved memory for the name when closing down. \param pt_cbs A struct containing the callbacks to the customer side
 * implementation. \param userdata The user data \param connection Reference to running connection. Must be passed to
 * protocol translator API functions.
 *
 * \return 1 if there is an error in configuring or starting the event loop.\n
 *         The function returns when the event loop is shut down and the return value is 0.
 */
DEPRECATED(
    int pt_client_start(const char *socket_path,
                        const char *name,
                        const protocol_translator_callbacks_t *pt_cbs,
                        void *userdata,
                        connection_t **connection));

/**
 * \brief Gracefully shuts down the protocol translator client.
 * \deprecated The protocol translator API v1 is deprecated. The API will exist until end of 2019.
 */
DEPRECATED(void pt_client_shutdown(connection_t *connection));

/**
 * @}
 * Close EDGE_PT_API Doxygen group definition
 */

#endif /* PT_API_H_ */
