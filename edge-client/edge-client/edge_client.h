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
#include "edge-client/edge_client_byoc.h"
#include "edge-client/request_context.h"
#include "sn_coap_header.h"
#include "mbed-client/coap_response.h"
#include "mbed-cloud-client/est_defs.h"
#include "certificate-enrollment-client/ce_status.h"
#include "certificate-enrollment-client/ce_defs.h"

/**
 * \brief Used to read resource attributes
 */
typedef struct edgeclient_resource_attributes_s {
    Lwm2mResourceType type;
    uint32_t operations_allowed;
} edgeclient_resource_attributes_t;

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
 * \brief callback for handling the registration of the Edge
 */
typedef void(*handle_register_cb) (void);

/**
 * \brief callback for handling the unregistration of the Edge
 */
typedef void(*handle_unregister_cb) (void);

/**
 * \brief callback for handling errors of the Edge
 */
typedef void(*handle_error_cb) (int error_code, const char *error_description);

/**
 * \brief callback for handling certificate renewal status callback.
 * \param certificate_name Name of certificate whose renewal process finished.
 * \param status Status of the finished renewal process.
 * \param initiator Initiator of the renewal process.
 * \return 0 - for successful write to protocol translator.
 *         1 - for failed write to protocol translator.
 */
typedef int (*handle_cert_renewal_status_cb)(const char *certificate_name,
                                             ce_status_e status,
                                             ce_initiator_e initiator,
                                             void *ctx);

/**
 * \brief callback for handling EST enrollment status callback.
 * \param status Status of the finished EST enrollment process.
 * \param cert_chain Certificate chain context containing the certificates that were enrolled.
 * \param ctx User provided context.
 * \return 0 - for successful write to protocol translator.
 *         1 - for failed write to protocol translator.
 */
typedef int (*handle_est_status_cb)(est_enrollment_result_e result,
                                    struct cert_chain_context_s *cert_chain,
                                    void *ctx);

/**
 * \brief Parameters required for edgeclient_create.
 * \param reset_storage specifies if Edge Client should remove and recreate the Device Management Client configuration data.
 */
typedef struct {
    handle_write_to_pt_cb handle_write_to_pt_cb;
    handle_register_cb handle_register_cb;
    handle_unregister_cb handle_unregister_cb;
    handle_error_cb handle_error_cb;
    handle_cert_renewal_status_cb handle_cert_renewal_status_cb;
    handle_est_status_cb handle_est_status_cb;
    void *cert_renewal_ctx;
    bool reset_storage;
} edgeclient_create_parameters_t;

/**
 * \brief Calls Edge Client's Protocol Translator handle write call-back function.
 * \param request_context current request context data
 * \param ctx Endpoint context data.
 * \return 0 if request was successfully sent.
 *         1 if request couldn't be sent.
 */
int edgeclient_write_to_pt_cb(edgeclient_request_context_t *request_ctx, void *ctx);

/**
 * \brief Calls Edge Client's Protocol Translator handle cert renewal status callback.
 * \param certificate_name Name of certificate whose renewal process finished.
 * \param status Status of the finished renewal process.
 * \param initiator Initiator of the renewal process.
 * \return 0 if status was successfully sent.
 *         1 if status couldn't be sent.
 */
int edgeclient_send_cert_renewal_status(const char *certificate_name, int status, int initiator);

/**
 * \brief Loads the Device Management Client credentials (either your own CA or a developer certificate) and sets up the
 *        callback handlers.
 */
void edgeclient_create(const edgeclient_create_parameters_t *params, byoc_data_t *byoc_data);

/**
 * \brief Shutdown and destroy the Device Management Client instance.
 */
void edgeclient_destroy();

/**
 * \brief Starts the Device Management Client registration flow and publishes the readily created resources. If you want to add some Edge resources, you can add them before
 * this call so that they will be available when registration is complete.
 */
void edgeclient_connect();

/**
 * \brief Starts the Device Management Client registration update flow and publishes the resources created since the last update/registration.
 * \param mutex_action May be used to lock the mutex to avoid race condition.
 */
void edgeclient_update_register();

/**
 * \brief Starts the Device Management Client registration update flow only if it's necessary. See
 * set_update_register_client_needed().
 */
void edgeclient_update_register_conditional();

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
 * \brief Query whether an endpoint object with the given name already exists in Device Management Client.
 * \param endpoint_name The name to look for.
 * \return True if the endpoint exists in Device Management Client, otherwise false.
 */
bool edgeclient_endpoint_exists(const char *endpoint_name);

/**
 * \brief Create an endpoint object with given name to Device Management Client. In success, the new endpoint object will be published at the next
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
 * \brief Create an object with given ID to Device Management Client or to endpoint with given name. In success, the new object will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of the endpoint under which the object should be located. It can also be NULL to create the object under Edge itself.
 * \param object_id The ID of the object to create, a 16-bit unsigned integer.
 * \return True if created successfully, otherwise false.
 */
bool edgeclient_add_object(const char *endpoint_name, const uint16_t object_id);

/**
 * \brief Create an object instance with given ID to a specific object. In success, the new object instance will be published at the next
 *  registration update or registration.
 * \param endpoint_name The name of the endpoint under which the object instance should be located. It can also be NULL to create the object instance under Edge itself.
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
 * \param endpoint_name The name of the endpoint under which the resource should be located. It can also be NULL to create the resource under Edge itself.
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
 * \brief Checks the type of existing resource.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a
 *        resource under Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned
 *        integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param attributes_out Pointer to the variable where the resource attributes are written.
 *                       See ::edgeclient_resource_attributes_t.
 * \return true  if the resource was found.
 *         false if the resource wasn't found.
 */
bool edgeclient_get_resource_attributes(const char *endpoint_name,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id,
                                        edgeclient_resource_attributes_t *attributes_out);

/**
 * \brief Returns the context (or connection) for the endpoint
 * \param endpoint_name Name of the endpoint
 * \param context_out pointer to the variable where the context pointer will be written
 * \return true  if endpoint was found. context_out pointer will be updated.
 *         false if endpoint was not found. context_out_pointer is set to NULL.
 */
bool edgeclient_get_endpoint_context(const char *endpoint_name, void **context_out);

/**
 * \brief Update a value to a resource with given path, consisting of endpoint_name (optional), object_id,
 *        object_instance_id and resource_id.
 *        If any of the path elements are missing, updating the resource value will fail.
 *        Using this method, it's not possible to set the type or the allowed operations of the resource.
 *        See also, `edgeclient_set_resource_value` which has less limitations.
 * \param endpoint_name The name of the endpoint under which the resource is located. It cannot be NULL.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned
 *        integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param value The const uint8_t* pointing to a new value buffer.
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
 * \return #PT_API_SUCCESS on success
 *         #PT_API_RESOURCE_NOT_FOUND - The resource was not found
 *         #PT_API_RESOURCE_NOT_WRITABLE - Write value failed, because the write operation is not allowed.
 *         #PT_API_INTERNAL_ERROR - The resource exists and is writable, but the writing failed anyway.
 */
pt_api_result_code_e edgeclient_update_resource_value(const char *endpoint_name,
                                                      const uint16_t object_id,
                                                      const uint16_t object_instance_id,
                                                      const uint16_t resource_id,
                                                      const uint8_t *value,
                                                      uint32_t value_length);
/**
 * \brief Set a value to a resource with given path, consisting of endpoint_name (optional), object_id, object_instance_id and resource_id.
 * If any of the path elements are missing, they will be created before setting the value.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Edge itself.
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
 * \brief Send asynchronous response for the given resource. Use this API to send the asynchronous response after
 *        getting a post or a request callback.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource
 *        under Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16-bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned
 *                           integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param token The token of the request given by the cloud client.
 * \param token_len The token length.
 * \param code The response code for this request.
 * \return #PT_API_SUCCESS on success
 *         Other codes on failure
 */
pt_api_result_code_e edgeclient_send_asynchronous_response(const char *endpoint_name,
                                                           const uint16_t object_id,
                                                           const uint16_t object_instance_id,
                                                           const uint16_t resource_id,
                                                           uint8_t *token,
                                                           uint8_t token_len,
                                                           coap_response_code_e code);

/**
 * \brief Get a pointer to the resource value buffer with given path, consisting of endpoint_name (optional), object_id, object_instance_id and resource_id.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a resource under Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16- bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param value_out A pointer to uint8_t*. After a successful call, this will point to the value buffer with the resource value. Client is responsible to free it.
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
 * \brief Get a pointer to the resource value buffer with given path, consisting of endpoint_name (optional),
 *        object_id, object_instance_id and resource_id.
 * \param endpoint_name The name of the endpoint under which the resource is located. It can also be NULL for a
 *        resource under Edge itself.
 * \param object_id The ID of the object under which the resource is located, a 16- bit unsigned integer.
 * \param object_instance_id The ID of the object instance under which the resource is located, a 16-bit unsigned
 *        integer.
 * \param resource_id The ID of the resource, a 16-bit unsigned integer.
 * \param value_out A pointer to uint8_t*. After a successful call, this will point to the value buffer with the
 *                  resource value. Client is responsible to free it.
 * \param value_length_out A pointer to the variable where the value length is stored.
 * \param attributes Pointer to a data structure where attributes are written. See ::edgeclient_resource_attributes_t.
 *                   Can be used to read for example, operations allowed and resource type.
 * \return true when the resource was found - value_out and value_length are updated.
 *         false when the resource was not found - value_out and value_length are not updated.
 */
bool edgeclient_get_resource_value_and_attributes(const char *endpoint_name,
                                                  const uint16_t object_id,
                                                  const uint16_t object_instance_id,
                                                  const uint16_t resource_id,
                                                  uint8_t **value_out,
                                                  uint32_t *value_length_out,
                                                  edgeclient_resource_attributes_t *attributes);

/**
 * \brief Initiate certificate renewal process for a certificate.
 * \param certificate_name The name of the certificate which should be renewed.
 * \return true when the renewal process is successfully initiated.
 *         false when the renewal process could not be initiated.
 */
pt_api_result_code_e edgeclient_renew_certificate(const char *certificate_name, int *detailed_error);

/**
 * \brief Initiate EST enrollment request.
 * \param certificate_name The name of the certificate which should be enrolled.
 * \param csr The certificate signing request to use when enrolling.
 * \param csr_length Length of the certificate signing request.
 * \param context User-supplied context.
 * \return true when the EST enrollment request is successfully initiated.
 *         false when the EST enrollment request could not be initiated.
 */
pt_api_result_code_e edgeclient_request_est_enrollment(const char *certificate_name,
                                                       uint8_t *csr,
                                                       const size_t csr_length,
                                                       void *context);

/**
 * \brief Get the internal id assigned to Edge Core device from Device Management.
 * \return The internal id string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_internal_id();

/**
 * \brief Get the account id assigned to Edge Core device from Device Management.
 * \return The account id string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_account_id();

/**
 * \brief Get the Lwm2m server URI assigned to Edge Core device from Device Management.
 * \return The Lwm2m server URI string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_lwm2m_server_uri();

/**
 * \brief Get the endpoint name assigned to Edge Core device.
 * \return The endpoint name string. The returned data pointer is borrowed to caller.
 */
const char* edgeclient_get_endpoint_name();

/**
 * \brief Check if Edge Client is shutting down. If it is, it's no longer allowed to send new data to Device Management.
 * \return true  if the shutdown process has started.
 *         false if shutdown proces hasn't been started.
 */
bool edgeclient_is_shutting_down();

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_WRAPPER_CLOUD_CLIENT_H_ */
