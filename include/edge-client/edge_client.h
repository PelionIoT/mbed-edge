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

#ifndef CLIENT_WRAPPER_CLOUD_CLIENT_H_
#define CLIENT_WRAPPER_CLOUD_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include "common/constants.h"
#include "common/pt_api_error_codes.h"

/**
 * \brief Used to specify if mutex should be reserved during calling a function.
 */
typedef enum {
    EDGECLIENT_DONT_LOCK_MUTEX,
    EDGECLIENT_LOCK_MUTEX
} edgeclient_mutex_action_e;

/**
 * \brief Request context for the Edge client.
 */
typedef struct edgeclient_request_context edgeclient_request_context_t;

/**
 * \brief Handler to call when response is available for Edge clients initiated requets.
 * \param ctx Request context which was passed in the original request.
 */
typedef void (*edgeclient_response_handler)(edgeclient_request_context_t *ctx);

typedef struct edgeclient_request_context {
    char *device_id; /**< The device id. */
    uint16_t object_id; /**< The object id. */
    uint16_t object_instance_id; /**< The object instance id. */
    uint16_t resource_id; /**< The resource id. */
    Lwm2mResourceType resource_type; /**< The resource type. */
    uint8_t *value; /**< The pointer to bytes resulting from decoding text format value to the correct data type. This will be passed to protocol translator. */
    uint32_t value_len; /**< The size of value buffer. */
    uint8_t operation; /**< The operation done to the resource. */
    edgeclient_response_handler success_handler; /**< The success handler to call on success response */
    edgeclient_response_handler failure_handler; /**< The failure handler to call on failure response */
    void *connection; /**< The connection context */
} edgeclient_request_context_t;

/**
 * \brief The request context deallocation function.
 * \param request_context The context to deallocate.
 */
void edgeclient_deallocate_request_context(edgeclient_request_context_t *request_context);

/**
 * \brief The request context allocation function.
 * \param uri The resource uri of the request.
 * \param value The value for performed action.
 * \param value_len The amount of bytes in the value.
 * \param operation The performed operation
 *        #OPERATION_WRITE or #OPERATION_EXECUTE
 * \param resource_type Data type of the resource.
 * \param success_handler The handler function to call on success response.
 * \param failure_handler The handler function to call on failure response.
 * \param connection The supplied connection context.
 */
edgeclient_request_context_t *edgeclient_allocate_request_context(
    const char *uri, const uint8_t *value,
    uint32_t value_len, uint8_t operation,
    Lwm2mResourceType resource_type,
    edgeclient_response_handler success_handler,
    edgeclient_response_handler failure_handler,
    void *connection);

/**
 * \brief callback for handling request writes to protocol translator
 *        The client should not deallocate the uri or the value.
 * \param request_ctx The request context to pass back to response handlers.
 * \param connection The connection to write the request.
 * \return 0 - for successful write to protocol translator.
 *         1 - for failed write to protocol translator.
 */
typedef int(*handle_write_to_pt_cb) (edgeclient_request_context_t *request_ctx, void *connection);

/**
 * \brief callback for handling the registration of the Mbed Edge
 */
typedef void(*handle_register_cb) (void);

/**
 * \brief callback for handling the unregistration of the Mbed Edge
 */
typedef void(*handle_unregister_cb) (void);

/**
 * \brief callback for handling errors of the Mbed Edge
 */
typedef void(*handle_error_cb) (int error_code, const char *error_description);

/**
 * \brief Parameters required for edgeclient_create.
 * \param reset_storage specifies if Edge Client should remove and recreate the Mbed Cloud Client configuration data.
 */
typedef struct {
    handle_write_to_pt_cb handle_write_to_pt_cb;
    handle_register_cb handle_register_cb;
    handle_unregister_cb handle_unregister_cb;
    handle_error_cb handle_error_cb;
    bool reset_storage;
} edgeclient_create_parameters_t;

/**
 * \brief Loads the Mbed Cloud Client credentials (either your own CA or a developer certificate) and sets up the
 *        callback handlers.
 */
void edgeclient_create(const edgeclient_create_parameters_t *params);

/**
 * \brief Shutdown and destroy the Mbed Cloud Client instance.
 */
void edgeclient_destroy();

/**
 * \brief Starts the Cloud Client registration flow and publishes the readily created resources. If you want to add some Mbed Edge resources, you can add them before
 * this call so that they will be available when registration is complete.
 */
void edgeclient_connect();

/**
 * \brief Starts the Cloud Client registration update flow and publishes the resources created since the last update/registration.
 * \param mutex_action May be used to lock the mutex to avoid race condition.
 */
void edgeclient_update_register(edgeclient_mutex_action_e mutex_action);

/**
 * \brief Starts the Cloud Client registration update flow only if it's necessary. See
 * set_update_register_client_needed().
 * \param mutex_action May be used to lock the mutex to avoid race condition.
 */
void edgeclient_update_register_conditional(edgeclient_mutex_action_e mutex_action);

/**
 * \brief Remove objects that have been added by this client.
 * \param client_context The context relating to the client. It will be used in choosing the objects to delete.
 * \return number of objects removed.
 */
uint32_t edgeclient_remove_objects_owned_by_client(void *client_context);

/**
 * \brief Remove resources that have been added by this client.
 * \param client_context The context relating to the client. It will be used in choosing the resources to delete.
 */
bool edgeclient_remove_resources_owned_by_client(void *client_context);

/**
 * \brief Stops the edge client safely so that we can exit the program.
 */
bool edgeclient_stop();

/**
 * \brief Query whether an endpoint object with the given name already exists in Cloud Client.
 * \param endpoint_name The name to look for.
 * \return True if the endpoint exists in Cloud Client, otherwise false.
 */
bool edgeclient_endpoint_exists(const char *endpoint_name);

/**
 * \brief Create an endpoint object with given name to Cloud Client. In success, the new endpoint object will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of endpoint object to create.
 * \param ctx User supplied data pointer
 * \return True if created successfully, otherwise false.
 */
bool edgeclient_add_endpoint(const char *endpoint_name, void *ctx);

/**
 * \brief Remove the endpoint object with the given name from the cloud client. If the removal is successful, the endpoint object will be removed
 *  in the next registration update or registration.
 * \param endpoint_name Name of endpoint object to remove
 * \return True is something was removed, false if remove failed or endpoint was not found.
 */
bool edgeclient_remove_endpoint(const char *endpoint_name);

/**
 * \brief Create an object with given ID to Cloud Client or to endpoint with given name. In success, the new object will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of the endpoint under which the object should be located. It can also be NULL to create the object under Mbed Edge itself.
 * \param object_id The ID of the object to create, a 16-bit unsigned integer.
 * \return True if created successfully, otherwise false.
 */
bool edgeclient_add_object(const char *endpoint_name, const uint16_t object_id);

/**
 * \brief Create an object instance with given ID to a specific object. In success, the new object instance will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of the endpoint under which the object instance should be located. It can also be NULL to create the object instance under Mbed Edge itself.
 * \param object_id The ID of the object under which the object instance should be created, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance to create, a 16-bit unsigned integer.
 * \return True if created successfully, otherwise false.
 */
bool edgeclient_add_object_instance(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id);

/**
 * \brief remove an object instance with given id to specific object. If removing is successful, the deleted object instance will be published in the next
 *  registration update or registration.
 * \param endpoint_name Name of endpoint under which the object instance exists, can also be NULL to object instance to be removed is under gateway itself
 * \param object_id Id of object the under which the object instance exists, a 16bit unsigned integer
 * \param object_instance_id Id of the object instance to remove, a 16bit unsigned integer
 * \return True if removing was successful, false otherwise
 */
bool edgeclient_remove_object_instance(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id);

/**
 * \brief Create a resource with given ID to a specific object instance. In success, the new resource will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of the endpoint under which the resource should be located. It can also be NULL to create the resource under Mbed Edge itself.
 * \param object_id The ID of the object under which the resource should be created, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource should be created, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource to create, a 16-bit unsigned integer.
 * \param resource_type Type of the resource
 * \param opr Operations allowed on the resource
 * \param connection is the current connection.
 * \return True if created successfully, otherwise false.
 */
bool edgeclient_add_resource(const char *endpoint_name,
                             const uint16_t object_id,
                             const uint16_t object_instance_id,
                             const uint16_t resource_id,
                             Lwm2mResourceType resource_type,
                             int opr,
                             void *connection);

/**
 * \brief Checks that the given value is valid for the given resource_type.
 *        For example, the size of bool must be one byte.
 * \param value is the value that needs to be verified. It is in binary network byte-order.
 * \param value_length is the length of the value buffer.
 * \param resource_type of the type of the value.
 */
bool edgeclient_verify_value(const uint8_t *value, const uint32_t value_length, Lwm2mResourceType resource_type);

/**
 * \brief Set a value to a resource with given path, consisting of endpoint_name (optional), object_id, object_instance_id and resource_id.
 * If any of the path elements are missing, they will be created before setting the value.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Mbed Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param value const The uint8_t* pointing to a new value buffer.
 *        For different LWM2M data types there are byte-order restrictions:
 *        String: UTF-8
 *        Integer: binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *        Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *        Boolean: 8 bit unsigned integer with value 0 or 1.
 *        Opaque: sequence of binary data.
 *        Time: Same representation as Integer.
 *        Objlnk: Two 16 bit unsigned integers one beside the other.
 *                First is the Object ID and second is the Object Instance ID.
 *
 *        Refer to: OMA Lightweight Machine to Machine Technical Specification
 *        for data type specifications.
 * \param value_length The length of the new value.
 * \param resource_type Type of the resource
 * \param opr Operations that are valid on the resource
 * \param ctx User supplied data pointer
 * \return #PT_API_SUCCESS on success
 *         Other codes on failure
 */
pt_api_result_code_e edgeclient_set_resource_value(const char *endpoint_name,
                                                   const uint16_t object_id,
                                                   const uint16_t object_instance_id,
                                                   const uint16_t resource_id,
                                                   const uint8_t *value,
                                                   uint32_t value_length,
                                                   Lwm2mResourceType resource_type,
                                                   int opr,
                                                   void *ctx);

/**
 * \brief Set delayed response on the given resource. This API needs to be used if processing a resource callback of a
 *        POST request takes more than 1 second.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Mbed Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param delayed_response The delayed response value. If set true the client is responsible to call
 *        edgeclient_send_delayed_response when he has processed the callback from the cloud.
 * \return #PT_API_SUCCESS on success
 *         Other codes on failure
 */
pt_api_result_code_e edgeclient_set_delayed_response(const char *endpoint_name,
                                                     const uint16_t object_id,
                                                     const uint16_t object_instance_id,
                                                     const uint16_t resource_id,
                                                     bool delayed_response);

/**
 * \brief Send delayed response for the given resource. Use is API to send the delayed response after getting post
 *        request callback when you have set the delayed response on the resource by using
 *        edgeclient_set_delayed_response.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Mbed Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param delayed_response The delayed response value. If set true the client is responsible to call
 *        edgeclient_send_delayed_response when he has processed the callback from the cloud.
 * \return #PT_API_SUCCESS on success
 *         Other codes on failure
 */
pt_api_result_code_e edgeclient_send_delayed_response(const char *endpoint_name,
                                                      const uint16_t object_id,
                                                      const uint16_t object_instance_id,
                                                      const uint16_t resource_id);

/**
 * \brief Get a pointer to the resource value buffer with given path, consisting of endpoint_name (optional), object_id, object_instance_id and resource_id.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Mbed Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16- bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param value_out A pointer to uint8_t*. After a successful call, this will point to the value buffer with the resource value.
 * \param value_length_out A pointer to the variable where the value length is stored.
 * \return true when the resource was found - value_out and value_length are updated.
 *         false when the resource was not found - value_out and value_length are not updated.
 */
bool edgeclient_get_resource_value(const char *endpoint_name,
                                   const uint16_t object_id,
                                   const uint16_t object_instance_id,
                                   const uint16_t resource_id,
                                   uint8_t **value_out,
                                   uint32_t *value_length_out);

/**
 * \brief Get the internal id assigned to Edge Core device from Mbed Cloud.
 * \return The internal id string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_internal_id();

/**
 * \brief Get the endpoint name assigned to Edge Core device.
 * \return The endpoint name string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_endpoint_name();

/**
 * \brief Check if Edge Client is shutting down. If it is, it's no longer allowed to send new data to Mbed Cloud.
 * \return true  if the shutdown process has started.
 *         false if shutdown proces hasn't been started.
 */
bool edgeclient_is_shutting_down();

typedef void(*edge_execute_callback) (void *arguments);
typedef void(*edge_value_updated_callback) (const char* object_name);

pt_api_result_code_e edgeclient_set_value_update_callback(const uint16_t object_id,
                                                          const uint16_t object_instance_id,
                                                          const uint16_t resource_id,
                                                          edge_value_updated_callback callback);

pt_api_result_code_e edgeclient_set_execute_callback(const uint16_t object_id,
                                                     const uint16_t object_instance_id,
                                                     const uint16_t resource_id,
                                                     edge_execute_callback callback);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_WRAPPER_CLOUD_CLIENT_H_ */
