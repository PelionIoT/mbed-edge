/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "pt-client-2/pt_certificate_api.h"
#include "pt-client-2/pt_certificate_api_internal.h"
#include "pt-client-2/pt_certificate_parser.h"
#include "ns_list.h"
#include "pt-client-2/pt_api_internal.h"
#include "edge-rpc/rpc.h"
#include "mbed-trace/mbed_trace.h"
#include "common/apr_base64.h"

#define TRACE_GROUP "ptcert"

#define PT_CERTIFICATE_RENEWAL_OBJECT_ID          35011
#define PT_CERTIFICATE_RENEWAL_RENEW_RESOURCE_ID  27002
#define PT_CERTIFICATE_RENEWAL_STATUS_RESOURCE_ID 27003

typedef struct pt_certificate_item {
    ns_list_link_t link;
    char *name;
} pt_certificate_item_t;

typedef NS_LIST_HEAD(pt_certificate_item_t, link) pt_certificate_items_t;

struct pt_certificate_list {
    pt_certificate_items_t list;
};



void pt_device_cert_renewal_context_free(pt_device_cert_renewal_context_t *ctx)
{
    if (ctx) {
        free(ctx->device_id);
        free(ctx->cert_name);
        free(ctx);
    }
}

pt_certificate_list_t *pt_certificate_list_create()
{
    pt_certificate_list_t *list = calloc(1, sizeof(pt_certificate_list_t));
    if (list) {
        ns_list_init(&(list->list));
    }
    return list;
}

void pt_certificate_list_destroy(pt_certificate_list_t *list)
{
    ns_list_foreach_safe(pt_certificate_item_t, current, &(list->list))
    {
        free(current->name);
        free(current);
    }
    free(list);
}

pt_status_t pt_certificate_list_add(pt_certificate_list_t *list, const char *name)
{
    if (!list || !name) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    pt_certificate_item_t *item = calloc(1, sizeof(pt_certificate_item_t));
    if (!item) {
        return PT_STATUS_ALLOCATION_FAIL;
    }
    item->name = strdup((char *) name);
    if (!(item->name)) {
        free(item);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    ns_list_add_to_end(&(list->list), item);
    return PT_STATUS_SUCCESS;
}

EDGE_LOCAL void pt_handle_pt_certificates_set_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_certificates_set_success");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_certificates_set_response_handler)(customer_callback->success_handler))(customer_callback->connection_id,
                                                                                 customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_pt_certificates_set_failure(json_t *response, void *callback_data)
{
    tr_err("pt_handle_pt_certificates_set_failure");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_certificates_set_response_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                                 customer_callback->userdata);
}

pt_status_t pt_certificate_renewal_list_set(const connection_id_t connection_id,
                                            pt_certificate_list_t *list,
                                            pt_certificates_set_response_handler success_handler,
                                            pt_certificates_set_response_handler failure_handler,
                                            void *userdata)
{
    if (!list) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("certificate_renewal_list_set");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);
    json_t *json_certificates = json_array();
    if (message == NULL || params == NULL || customer_callback == NULL || json_certificates == NULL) {
        json_decref(message);
        json_decref(json_certificates);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    ns_list_foreach_safe(pt_certificate_item_t, cur, &(list->list))
    {
        json_array_append_new(json_certificates, json_string(cur->name));
    }
    json_object_set_new(params, "certificates", json_certificates);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_certificates_set_success,
                                               pt_handle_pt_certificates_set_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

EDGE_LOCAL void pt_handle_pt_certificate_renew_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_certificate_renew_success");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_certificate_renew_response_handler)(customer_callback->success_handler))(customer_callback->connection_id,
                                                                                  customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_pt_certificate_renew_failure(json_t *response, void *callback_data)
{
    tr_err("pt_handle_pt_certificate_renew_failure");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_certificate_renew_response_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                                  customer_callback->userdata);
}

pt_status_t pt_certificate_renew(const connection_id_t connection_id,
                                 const char *name,
                                 pt_certificate_renew_response_handler success_handler,
                                 pt_certificate_renew_response_handler failure_handler,
                                 void *userdata)
{
    json_t *message = allocate_base_request("renew_certificate");
    json_t *params = json_object_get(message, "params");
    json_t *json_name = json_string(name);
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);
    if (message == NULL || params == NULL || customer_callback == NULL || json_name == NULL) {
        json_decref(message);
        json_decref(json_name);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "certificate", json_name);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_certificate_renew_success,
                                               pt_handle_pt_certificate_renew_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

EDGE_LOCAL void pt_handle_device_certificate_renew_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_est_request_enrollment_success");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;

    struct cert_chain_context_s *cert_chain = (struct cert_chain_context_s *) calloc(1, sizeof(struct cert_chain_context_s));
    json_t *cert_array = json_object_get(json_object_get(response, "result"), "certificate_data");
    size_t cert_count = json_array_size(cert_array);
    bool success = true;
    if (cert_chain != NULL && cert_array != NULL && cert_count > 0) {
        cert_chain->chain_length = cert_count;
        struct cert_context_s **cur_ctx_ptr = &cert_chain->certs;
        for (size_t cert_index = 0; cert_index < cert_count; cert_index++) {
            json_t *cert_handle = json_array_get(cert_array, cert_index);
            const char *cert_encoded = json_string_value(cert_handle);

            struct cert_context_s *cert_ctx = (struct cert_context_s *) calloc(1, sizeof(struct cert_context_s));
            *cur_ctx_ptr = cert_ctx;
            if (cert_ctx == NULL || cert_encoded == NULL) {
                success = false;
                break;
            }

            size_t decoded_size = apr_base64_decode_len(cert_encoded);
            if (decoded_size == 0) {
                success = false;
                break;
            }

            cert_ctx->cert = (uint8_t *) calloc(1, decoded_size);
            if (cert_ctx->cert == NULL) {
                success = false;
                break;
            }

            size_t actual_size = apr_base64_decode_binary((unsigned char *) cert_ctx->cert, (const char *) cert_encoded);
            assert(decoded_size >= actual_size);
            cert_ctx->cert_length = actual_size;
            cur_ctx_ptr = &cert_ctx->next;
        }

        if (success == false) {
            pt_free_certificate_chain_context(cert_chain);
            cert_chain = NULL;
        }
    }
    else {
        free(cert_chain);
        cert_chain = NULL;
        success = false;
    }

    void *userdata = NULL;
    const char *device_id = NULL;
    const char *cert_name = NULL;
    pt_device_cert_renewal_context_t *ctx = (pt_device_cert_renewal_context_t *) customer_callback->userdata;
    if (ctx) {
        userdata = ctx->userdata;
        device_id = ctx->device_id;
        cert_name = ctx->cert_name;
    }

    if (success == false || device_id == NULL || cert_name == NULL) {
        ((pt_device_certificate_renew_response_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                                             device_id,
                                                                                             cert_name,
                                                                                             CE_STATUS_EST_ERROR,
                                                                                             cert_chain,
                                                                                             userdata);
    }
    else {
        ((pt_device_certificate_renew_response_handler)(customer_callback->success_handler))(customer_callback->connection_id,
                                                                                             device_id,
                                                                                             cert_name,
                                                                                             CE_STATUS_SUCCESS,
                                                                                             cert_chain,
                                                                                             userdata);
    }
    pt_device_cert_renewal_context_free(ctx);
}

EDGE_LOCAL void pt_handle_device_certificate_renew_failure(json_t *response, void *callback_data)
{
    if (callback_data == NULL) {
        tr_err("pt_handle_device_certificate_renew_failure missing callback data!");
        return;
    }

    tr_warn("pt_handle_device_certificate_renew_failure");

    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;

    void *userdata = NULL;
    const char *device_id = NULL;
    const char *cert_name = NULL;
    pt_device_cert_renewal_context_t *ctx = (pt_device_cert_renewal_context_t *) customer_callback->userdata;
    if (ctx) {
        userdata = ctx->userdata;
        device_id = ctx->device_id;
        cert_name = ctx->cert_name;
    }
    ((pt_device_certificate_renew_response_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                                         device_id,
                                                                                         cert_name,
                                                                                         CE_STATUS_EST_ERROR,
                                                                                         NULL,
                                                                                         userdata);
    pt_device_cert_renewal_context_free(ctx);
}

void pt_free_certificate_chain_context(struct cert_chain_context_s *context) {
    if (context) {
        struct cert_context_s *next_cert = context->certs;
        while (next_cert != NULL) {
            struct cert_context_s *temp = next_cert->next;
            free(next_cert->cert);
            free(next_cert);
            next_cert = temp;
        }
        free(context);
    }
}

typedef struct cert_request_data_s {
    const char *cert_name;
    const char *request_id;
    size_t request_id_len;
} cert_request_data_t;

EDGE_LOCAL bool is_supported_type(ce_tlv_type_e type) {
    switch(type) {
    case CE_TLV_TYPE_CERT_NAME:
    case CE_TLV_TYPE_REQUEST_ID:
        return true;
    default:
        return false;
    }
}

EDGE_LOCAL pt_ce_status_e certificate_renew_parse_request(const uint8_t *data, const size_t size, cert_request_data_t *request_data)
{
    ce_tlv_status_e status;
    ce_tlv_element_s element;

    if (request_data == NULL) {
        return CE_STATUS_INVALID_PARAMETER;
    }

    memset(request_data, 0, sizeof(cert_request_data_t));

    if (ce_tlv_parser_init(data, size, &element) != CE_TLV_STATUS_SUCCESS) {
        return CE_STATUS_BAD_INPUT_FROM_SERVER;
    }

    while ((status = ce_tlv_parse_next(&element)) != CE_TLV_STATUS_END) {
        if (status != CE_TLV_STATUS_SUCCESS) {
            // something got wrong while parsing
            return CE_STATUS_BAD_INPUT_FROM_SERVER;
        }

        // element parsed successfully - check if type supported

        if ((is_supported_type(element.type & ~(1 << CE_MSB(element.type))) == false) && (is_required(&element))) {
            return CE_STATUS_BAD_INPUT_FROM_SERVER;
        } else if ((is_supported_type(element.type & ~(1 << CE_MSB(element.type))) == false) && (!is_required(&element))) {
            // unsupported type but optional - ignored
            continue;
        }

        switch (element.type & ~(1 << CE_MSB(element.type))) {
        case CE_TLV_TYPE_CERT_NAME:
            request_data->cert_name = element.val.text;
            tr_debug("Parser certificate name '%s'", request_data->cert_name);
            break;
        case CE_TLV_TYPE_REQUEST_ID:
            request_data->request_id = (const char *) element.val.bytes;
            request_data->request_id_len = element.len;
            tr_debug("Parser request id '%.*s'", (int)request_data->request_id_len, request_data->request_id);
            break;
        default:
            break;
        }
    }

    if (request_data->cert_name == NULL || request_data->request_id == NULL || request_data->request_id_len == 0) {
        // parsing succeeded however we haven't got a concrete certificate name
        return CE_STATUS_BAD_INPUT_FROM_SERVER;
    }

    return CE_STATUS_SUCCESS;
}

EDGE_LOCAL void certificate_renew_execute_success_handler(connection_id_t connection_id, const char *device_id, void *ctx)
{
    (void) connection_id;
    tr_debug("Certificate renew status sent sucessfully.");
}

EDGE_LOCAL void certificate_renew_execute_failure_handler(connection_id_t connection_id, const char *device_id, void *ctx)
{
    (void) connection_id;
    tr_debug("Certificate renew status sending failed.");
}

EDGE_LOCAL pt_status_t pt_device_certificate_renew_set_execute_status(const connection_id_t connection_id,
                                                                      const char *device_id,
                                                                      pt_ce_status_e status)
{
    size_t buf_size = snprintf(NULL, 0, "%"PRId32, status);
    uint8_t *buf = malloc(buf_size + 1);
    if (buf == NULL) {
        return PT_STATUS_ALLOCATION_FAIL;
    }
    snprintf((char *) buf, buf_size + 1, "%"PRId32, status);

    pt_device_set_resource_value(connection_id,
                                 device_id,
                                 PT_CERTIFICATE_RENEWAL_OBJECT_ID,
                                 0,
                                 PT_CERTIFICATE_RENEWAL_RENEW_RESOURCE_ID,
                                 buf,
                                 buf_size,
                                 free);
    return pt_device_write_values(connection_id, device_id, certificate_renew_execute_success_handler, certificate_renew_execute_failure_handler, NULL);
}

pt_status_t pt_device_certificate_renew_resource_callback(const connection_id_t connection_id,
                                                          const char *device_id,
                                                          const uint16_t object_id,
                                                          const uint16_t object_instance_id,
                                                          const uint16_t resource_id,
                                                          const uint8_t operation,
                                                          const uint8_t *value,
                                                          const uint32_t size,
                                                          void *userdata)
{
    if (value == NULL || size == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    api_lock();

    connection_t *connection = find_connection(connection_id);
    if (connection == NULL || connection->client == NULL) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    if (connection->client->protocol_translator_callbacks == NULL || connection->client->protocol_translator_callbacks->device_certificate_renew_request_cb == NULL) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    pt_device_certificate_renew_request_handler renew_request_handler = connection->client->protocol_translator_callbacks->device_certificate_renew_request_cb;
    void *client_userdata = connection->client->userdata;

    // Store the request id for when we send back the result notification
    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device == NULL) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    // After this point the status of the operation will be set in the status resource,
    // so we MUST return success so that the execute operation will appear successful
    // on cloud side, errors will be passed in the status resource.

    cert_request_data_t request_data = {0};
    pt_ce_status_e status = certificate_renew_parse_request(value, size, &request_data);
    if (status != CE_STATUS_SUCCESS) {
        api_unlock();
        pt_device_certificate_renew_set_execute_status(connection_id, device_id, status);
        return PT_STATUS_SUCCESS;
    }

    if (device->csr_request_id != NULL) {
        // A request is already ongoing
        api_unlock();
        pt_device_certificate_renew_set_execute_status(connection_id, device_id, CE_STATUS_DEVICE_BUSY);
        return PT_STATUS_SUCCESS;
    }

    device->csr_request_id = (char *) calloc(1, request_data.request_id_len);
    if (device->csr_request_id == NULL) {
        // Allocation failed
        api_unlock();
        pt_device_certificate_renew_set_execute_status(connection_id, device_id, CE_STATUS_OUT_OF_MEMORY);
        return PT_STATUS_SUCCESS;
    }
    memcpy(device->csr_request_id, request_data.request_id, request_data.request_id_len);
    device->csr_request_id_len = request_data.request_id_len;

    api_unlock();

    pt_status_t pt_status = renew_request_handler(connection_id, device_id, request_data.cert_name, client_userdata);

    if (pt_status != PT_STATUS_SUCCESS) {
        pt_device_certificate_renew_set_execute_status(connection_id, device_id, CE_STATUS_ERROR);

        api_lock();
        free(device->csr_request_id);
        device->csr_request_id = NULL;
        device->csr_request_id_len = 0;
        api_unlock();

        return PT_STATUS_SUCCESS;
    }

    pt_device_certificate_renew_set_execute_status(connection_id, device_id, CE_STATUS_PENDING);

    return PT_STATUS_SUCCESS;
}

pt_status_t pt_device_init_certificate_renewal_resources(connection_id_t connection_id, const char *device_id)
{
    if (device_id == NULL || pt_device_exists(connection_id, device_id) == false) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    uint32_t flags = 0;
    pt_status_t status = pt_device_get_feature_flags(connection_id, device_id, &flags);
    if (status != PT_STATUS_SUCCESS) {
        return status;
    }

    if ((flags & PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL) == 0) {
        tr_err("Trying to create certificate renewal resources but the feature is disabled.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    if (pt_device_resource_exists(connection_id, device_id, PT_CERTIFICATE_RENEWAL_OBJECT_ID, 0, PT_CERTIFICATE_RENEWAL_RENEW_RESOURCE_ID)) {
        tr_err("Certificate renewal resources already exist!");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    status = pt_device_add_resource_with_callback(connection_id,
                                                  device_id,
                                                  PT_CERTIFICATE_RENEWAL_OBJECT_ID,
                                                  0,
                                                  PT_CERTIFICATE_RENEWAL_RENEW_RESOURCE_ID,
                                                  LWM2M_STRING,
                                                  OPERATION_EXECUTE,
                                                  NULL,
                                                  0,
                                                  free,
                                                  pt_device_certificate_renew_resource_callback);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create certificate renewal resources! Error was %d", status);
        return status;
    }

    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    PT_CERTIFICATE_RENEWAL_OBJECT_ID,
                                    0,
                                    PT_CERTIFICATE_RENEWAL_STATUS_RESOURCE_ID,
                                    LWM2M_OPAQUE,
                                    NULL,
                                    0,
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create certificate renewal resources! Error was %d", status);
        return status;
    }

    return PT_STATUS_SUCCESS;
}

pt_status_t pt_device_certificate_renew(const connection_id_t connection_id,
                                        const char *device_id,
                                        const char *name,
                                        const char *csr,
                                        const size_t csr_length,
                                        pt_device_certificate_renew_response_handler success_handler,
                                        pt_device_certificate_renew_response_handler failure_handler,
                                        void *userdata)
{
    if (name == NULL || csr == NULL || csr_length == 0 || success_handler == NULL || failure_handler == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    uint32_t features = 0;
    if (pt_device_get_feature_flags(connection_id, device_id, &features) != PT_STATUS_SUCCESS ||
        (features & PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL) == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    json_t *message = allocate_base_request("est_request_enrollment");
    json_t *params = json_object_get(message, "params");
    json_t *json_name = json_string(name);
    char *csr_encoded = calloc(1, apr_base64_encode_len(csr_length));
    if (csr_encoded) {
        apr_base64_encode_binary(csr_encoded, (const unsigned char *) csr, csr_length);
    }

    pt_device_cert_renewal_context_t *ctx = (pt_device_cert_renewal_context_t *) calloc(1, sizeof(pt_device_cert_renewal_context_t));
    char *ctx_device_id = strdup(device_id);
    char *ctx_cert_name = strdup(name);
    if (ctx == NULL || ctx_device_id == NULL || ctx_cert_name == NULL) {
        free(ctx);
        free(ctx_device_id);
        free(ctx_cert_name);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    ctx->device_id = ctx_device_id;
    ctx->cert_name = ctx_cert_name;
    ctx->userdata = userdata;

    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           ctx);
    if (message == NULL || params == NULL || customer_callback == NULL || json_name == NULL || csr_encoded == NULL) {
        json_decref(message);
        json_decref(json_name);
        free(csr_encoded);
        pt_device_cert_renewal_context_free(ctx);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "certificate_name", json_name);
    json_object_set_new(params, "csr", json_string(csr_encoded));

    free(csr_encoded);

    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_device_certificate_renew_success,
                                               pt_handle_device_certificate_renew_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

pt_status_t pt_device_certificate_renew_request_finish(const connection_id_t connection_id,
                                                       const char *device_id,
                                                       const pt_ce_status_e status)
{
    if (device_id == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    api_lock();

    connection_t *connection = find_connection(connection_id);
    if (connection == NULL || connection->client == NULL) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device == NULL) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    if (device->csr_request_id == NULL) {
        api_unlock();
        return PT_STATUS_UNNECESSARY;
    }

    char *request_id = device->csr_request_id;
    size_t request_id_len = device->csr_request_id_len;
    device->csr_request_id = NULL;
    device->csr_request_id_len = 0;
    api_unlock();

    size_t tlv_size = 4 + request_id_len + 1 + 7;
    char *tlv_buf = calloc(1, tlv_size);
    if (tlv_buf == NULL) {
        return PT_STATUS_ALLOCATION_FAIL;
    }

    ce_tlv_encoder_s encoder = {0};
    ce_tlv_encoder_init((uint8_t *) tlv_buf, tlv_size, &encoder);
    ce_tlv_status_e tlv_status = tlv_add_uint16(CE_TLV_TYPE_STATUS, status, true, &encoder);
    if (tlv_status != CE_TLV_STATUS_SUCCESS) {
        free(tlv_buf);
        free(request_id);
    }
    tlv_status = tlv_add_bytes(CE_TLV_TYPE_REQUEST_ID, request_id_len, request_id, false, &encoder);
    if (tlv_status != CE_TLV_STATUS_SUCCESS) {
        free(tlv_buf);
        return PT_STATUS_ERROR;
    }

    pt_device_set_resource_value(connection_id,
                                 device_id,
                                 PT_CERTIFICATE_RENEWAL_OBJECT_ID,
                                 0,
                                 PT_CERTIFICATE_RENEWAL_STATUS_RESOURCE_ID,
                                 encoder.buf,
                                 encoder.encoded_length,
                                 free);
    pt_status_t pt_status = pt_device_write_values(connection_id, device_id, certificate_renew_execute_success_handler, certificate_renew_execute_failure_handler, NULL);
    if (pt_status == PT_STATUS_SUCCESS) {
        free(request_id);
    }
    return pt_status;
}
