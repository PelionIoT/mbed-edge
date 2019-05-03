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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 // needed for asptrinf
#endif

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <assert.h>
#include <stdio.h>

#include "edge-core/protocol_api_internal.h"
#include "edge-core/protocol_crypto_api.h"
#include "edge-core/protocol_crypto_api_internal.h"
#include "edge-core/edge_server.h"
#include "jsonrpc/jsonrpc.h"
#include "edge-rpc/rpc.h"
#include "common/apr_base64.h"

#include "edge-client/edge_client.h"
#include "eventOS_scheduler.h"
#include "eventOS_event.h"

#include "key_config_manager.h"

#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"

#define TRACE_GROUP "serv"

typedef struct crypto_api_event_request_context_ {
    uint8_t *data_name;
    connection_id_t connection_id;
    char *request_id;
    kcm_item_type_e data_type;
    const char *json_key_name;
    const char *json_value_name;
} crypto_api_event_request_context_t;

EDGE_LOCAL int8_t crypto_api_tasklet_id = -1;

static void crypto_api_get_kcm_data_event(arm_event_t *event);

EDGE_LOCAL void crypto_api_event_handler(arm_event_t *event)
{
    switch(event->event_id) {
    case CRYPTO_API_EVENT_INIT:
        tr_debug("Crypto RPC API initialized");
        break;
    case CRYPTO_API_EVENT_GET_KCM_DATA:
        crypto_api_get_kcm_data_event(event);
        break;
    default:
        break;
    }
}

void crypto_api_protocol_init()
{
    if (crypto_api_tasklet_id == -1) {
        eventOS_scheduler_mutex_wait();
        crypto_api_tasklet_id = eventOS_event_handler_create(crypto_api_event_handler, CRYPTO_API_EVENT_INIT);
        eventOS_scheduler_mutex_release();
        if (crypto_api_tasklet_id < 0) {
            tr_error("Crypto API protocol initialization failed!");
        }
    }
    else {
        tr_warning("Crypto API protocol initialized multiple times!");
    }
}

void crypto_api_protocol_destroy()
{
    // Note: currently there seems to be no way to destroy the tasklet.
    crypto_api_tasklet_id = -1;
}

int crypto_api_get_certificate(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return 1;
    }

    if (!pt_api_check_request_id(jt)) {
        tr_warn("Get certificate failed. No request id was given.");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Get certificate failed. No request id was given."));
        return 1;
    }

    json_t *cert_name_handle = json_object_get(json_params, "certificate");
    if (cert_name_handle == NULL || json_string_length(cert_name_handle) == 0) {
        tr_warn("Get certificate failed. Missing or empty certificate field.");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Get certificate failed. Missing or empty certificate field."));
        return 1;
    }

    arm_event_t ev = {0};
    crypto_api_event_request_context_t *ctx = calloc(1, sizeof(crypto_api_event_request_context_t));
    if (ctx) {
        ctx->request_id = strdup(json_string_value(json_object_get(request, "id")));
        ctx->data_name = (uint8_t *) strdup(json_string_value(cert_name_handle));
        ctx->data_type = KCM_CERTIFICATE_ITEM;
        ctx->json_key_name = "certificate_name";
        ctx->json_value_name = "certificate_data";
    }
    if (!ctx || !ctx->data_name || !ctx->request_id) {
        goto error_exit;
    }
    ev.event_id = CRYPTO_API_EVENT_GET_KCM_DATA;
    ctx->connection_id = connection->id;

    ev.data_ptr = ctx;
    ev.receiver = crypto_api_tasklet_id;
    int status = eventOS_event_send(&ev);

    if (status != 0) {
        tr_warn("Could not send crypto API event.");
        *result = jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                       pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                       json_string("Could not send crypto api event."));
        goto error_exit;
        return 1;
    }

    return -1; // OK so far, but the response is provided later.
error_exit:
    if (ctx) {
        free(ctx->data_name);
        free(ctx->request_id);
    }
    free(ctx);
    return 1;
}

static void crypto_api_write_free_func(rpc_request_context_t *userdata)
{
    crypto_api_event_request_context_t *ctx = (crypto_api_event_request_context_t *) userdata;
    tr_debug("Handling cryptoapi write free operations.");
    free(ctx->data_name);
    free(ctx->request_id);
    free(ctx);
}

typedef struct {
    kcm_status_e status;
    const char *description;
} kcm_enum_map_t;

static const char *map_kcm_status_to_string(kcm_status_e status)
{
    const char *result = NULL;
    static kcm_enum_map_t enum_map[] =
            {{KCM_STATUS_SUCCESS, "KCM_STATUS_SUCCESS"},
             {KCM_STATUS_ERROR, "KCM_STATUS_ERROR"},
             {KCM_STATUS_INVALID_PARAMETER, "KCM_STATUS_INVALID_PARAMETER"},
             {KCM_STATUS_INSUFFICIENT_BUFFER, "KCM_STATUS_INSUFFICIENT_BUFFER"},
             {KCM_STATUS_OUT_OF_MEMORY, "KCM_STATUS_OUT_OF_MEMORY"},
             {KCM_STATUS_ITEM_NOT_FOUND, "KCM_STATUS_ITEM_NOT_FOUND"},
             {KCM_STATUS_META_DATA_NOT_FOUND, "KCM_STATUS_META_DATA_NOT_FOUND"},
             {KCM_STATUS_META_DATA_SIZE_ERROR, "KCM_STATUS_META_DATA_SIZE_ERROR"},
             {KCM_STATUS_FILE_EXIST, "KCM_STATUS_FILE_EXIST"},
             {KCM_STATUS_KEY_EXIST, "KCM_STATUS_KEY_EXIST"},
             {KCM_STATUS_NOT_PERMITTED, "KCM_STATUS_NOT_PERMITTED"},
             {KCM_STATUS_STORAGE_ERROR, "KCM_STATUS_STORAGE_ERROR"},
             {KCM_STATUS_ITEM_IS_EMPTY, "KCM_STATUS_ITEM_IS_EMPTY"},
             {KCM_STATUS_INVALID_FILE_VERSION, "KCM_STATUS_INVALID_FILE_VERSION"},
             {KCM_STATUS_FILE_CORRUPTED, "KCM_STATUS_FILE_CORRUPTED"},
             {KCM_STATUS_FILE_NAME_CORRUPTED, "KCM_STATUS_FILE_NAME_CORRUPTED"},
             {KCM_STATUS_INVALID_FILE_ACCESS_MODE, "KCM_STATUS_INVALID_FILE_ACCESS_MODE"},
             {KCM_STATUS_UNKNOWN_STORAGE_ERROR, "KCM_STATUS_UNKNOWN_STORAGE_ERROR"},
             {KCM_STATUS_NOT_INITIALIZED, "KCM_STATUS_NOT_INITIALIZED"},
             {KCM_STATUS_CLOSE_INCOMPLETE_CHAIN, "KCM_STATUS_CLOSE_INCOMPLETE_CHAIN"},
             {KCM_STATUS_CORRUPTED_CHAIN_FILE, "KCM_STATUS_CORRUPTED_CHAIN_FILE"},
             {KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN"},
             {KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED, "KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED"},
             {KCM_STATUS_FILE_NAME_TOO_LONG, "KCM_STATUS_FILE_NAME_TOO_LONG"},
             {KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE, "KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE"},
             {KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY, "KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY"},
             {KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY, "KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY"},
             {KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT, "KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT"},
             {KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY, "KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY"},
             {KCM_CRYPTO_STATUS_ECP_INVALID_KEY, "KCM_CRYPTO_STATUS_ECP_INVALID_KEY"},
             {KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION, "KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION"},
             {KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED, "KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED"},
             {KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED, "KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED"},
             {KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED, "KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED"},
             {KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG, "KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG"},
             {KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE, "KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE"},
             {KCM_CRYPTO_STATUS_PARSING_DER_CERT, "KCM_CRYPTO_STATUS_PARSING_DER_CERT"},
             {KCM_CRYPTO_STATUS_CERT_EXPIRED, "KCM_CRYPTO_STATUS_CERT_EXPIRED"},
             {KCM_CRYPTO_STATUS_CERT_FUTURE, "KCM_CRYPTO_STATUS_CERT_FUTURE"},
             {KCM_CRYPTO_STATUS_CERT_MD_ALG, "KCM_CRYPTO_STATUS_CERT_MD_ALG"},
             {KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE, "KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE"},
             {KCM_CRYPTO_STATUS_CERT_PUB_KEY, "KCM_CRYPTO_STATUS_CERT_PUB_KEY"},
             {KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED, "KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED"},
             {KCM_CRYPTO_STATUS_INVALID_X509_ATTR, "KCM_CRYPTO_STATUS_INVALID_X509_ATTR"},
             {KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED, "KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED"},
             {KCM_CRYPTO_STATUS_INVALID_MD_TYPE, "KCM_CRYPTO_STATUS_INVALID_MD_TYPE"},
             {KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE, "KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE"},
             {KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY, "KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY"},
             {KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY, "KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY"},
             {KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR, "KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR"},
             {KCM_CRYPTO_STATUS_INVALID_OID, "KCM_CRYPTO_STATUS_INVALID_OID"},
             {KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT, "KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT"},
             {KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR,
              "KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR"},
             {KCM_CRYPTO_STATUS_SET_EXTENSION_FAILED, "KCM_CRYPTO_STATUS_SET_EXTENSION_FAILED"},
             {KCM_STATUS_RBP_ERROR, "KCM_STATUS_RBP_ERROR"},
             {KCM_STATUS_FILE_NAME_INVALID, "KCM_STATUS_FILE_NAME_INVALID"},
             {KCM_CRYPTO_STATUS_INVALID_PK_PRIVKEY, "KCM_CRYPTO_STATUS_INVALID_PK_PRIVKEY"},
             {-1, "KCM_UNKNOWN_STATUS"}};
    int32_t index;
    for (index = 0; enum_map[index].status != (kcm_status_e) -1; index++) {
        if (status == enum_map[index].status) {
            break;
        }
    }
    result = enum_map[index].description;
    return result;
}

void crypto_api_get_kcm_data_event(arm_event_t *event)
{
    assert(event->data_ptr != NULL);
    crypto_api_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->data_name != NULL);

    uint8_t *data_buffer = NULL;
    size_t item_size = 0;
    char *desc = NULL;

    json_t *response = pt_api_allocate_response_common(ctx->request_id);
    json_t *result = NULL;
    kcm_status_e status = kcm_item_get_data_size(ctx->data_name,
                                                 strlen((char *) (ctx->data_name)),
                                                 ctx->data_type,
                                                 &item_size);
    if (status != KCM_STATUS_SUCCESS) {
        asprintf(&desc,
                 "Got error when reading item size from kcm, error %d (%s)",
                 status,
                 map_kcm_status_to_string(status));

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string(desc)));
        free(desc);
        goto send;
    }

    data_buffer = calloc(item_size, sizeof(uint8_t));
    if (data_buffer == NULL) {
        tr_error("Memory allocation error");
        goto send;
    }

    status = kcm_item_get_data(ctx->data_name,
                               strlen((char *) (ctx->data_name)),
                               ctx->data_type,
                               data_buffer,
                               item_size,
                               &item_size);
    if (status != KCM_STATUS_SUCCESS) {
        asprintf(&desc,
                 "Got error when reading item from kcm, error %d (%s)",
                 status,
                 map_kcm_status_to_string(status));
        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string(desc)));
        free(desc);
        goto send;
    }


    int encoded_length = apr_base64_encode_len(item_size);
    char *encoded_value = (char *) malloc(encoded_length);
    (void) apr_base64_encode_binary(encoded_value,
                                                   (const unsigned char *) data_buffer,
                                                   item_size);
    result = json_object();
    json_object_set_new(result, ctx->json_key_name, json_string((char *) (ctx->data_name)));
    json_object_set_new(result, ctx->json_value_name, json_string(encoded_value));
    json_object_set_new(response, "result", result);
    free(encoded_value);

send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        crypto_api_write_free_func,
                                                        (rpc_request_context_t *) ctx);
    free(data_buffer);
}

int crypto_api_get_public_key(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return 1;
    }

    if (!pt_api_check_request_id(jt)) {
        tr_warn("Get certificate failed. No request id was given.");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Get public key failed. No request id was given."));
        return 1;
    }

    json_t *key_name_handle = json_object_get(json_params, "key");
    if (key_name_handle == NULL || json_string_length(key_name_handle) == 0) {
        tr_warn("Get public key failed. Missing or empty key field.");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Get public key failed. Missing or empty key field."));
        return 1;
    }

    arm_event_t ev = {0};
    crypto_api_event_request_context_t *ctx = calloc(1, sizeof(crypto_api_event_request_context_t));
    if (ctx) {
        ctx->request_id = strdup(json_string_value(json_object_get(request, "id")));
        ctx->data_name = (uint8_t *) strdup(json_string_value(key_name_handle));
        ctx->data_type = KCM_PUBLIC_KEY_ITEM;
        ctx->json_key_name = "key_name";
        ctx->json_value_name = "key_data";
    }
    if (!ctx || !ctx->data_name || !ctx->request_id) {
        goto error_exit;
    }
    ev.event_id = CRYPTO_API_EVENT_GET_KCM_DATA;
    ctx->connection_id = connection->id;

    ev.data_ptr = ctx;
    ev.receiver = crypto_api_tasklet_id;
    int status = eventOS_event_send(&ev);

    if (status != 0) {
        tr_warn("Could not send crypto API event.");
        *result = jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                       pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                       json_string("Could not send crypto api event."));
        goto error_exit;
    }

    return -1; // OK so far, but the response is provided later.
error_exit:
    if (ctx) {
        free(ctx->data_name);
        free(ctx->request_id);
    }
    free(ctx);
    return 1;
}

