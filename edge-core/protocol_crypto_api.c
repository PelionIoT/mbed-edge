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
#define CRYPTO_SHARED_SECRET_BASE64_ENCODE_SIZE 47

typedef protocol_api_async_request_context_t crypto_api_event_request_context_t;

typedef struct crypto_api_asymmetric_event_request_context_ {
    uint8_t *key_name_ptr;  // Key name, can be either private or public key, depends on the event type
    uint8_t *hash_ptr;      // Hash digest base64 encoded
    uint8_t *signature_ptr; // Signature base64 encoded, can be NULL when used in asymmetric sign event
    connection_id_t connection_id;
    char *request_id;
} crypto_api_asymmetric_event_request_context_t;

typedef struct crypto_api_ecdh_event_request_context_ {
    uint8_t *private_key_name_ptr;  // Private key name
    uint8_t *peer_public_key_ptr;   // Peer public key base64 encoded
    connection_id_t connection_id;
    char *request_id;
} crypto_api_ecdh_event_request_context_t;

const char *error_desc_oom_message = "Out of memory, couldn't format description.";

EDGE_LOCAL int8_t crypto_api_tasklet_id = -1;

static void crypto_api_get_kcm_data_event(arm_event_t *event,
                                   kcm_item_type_e item_type,
                                   const char *json_key_name,
                                   const char *json_value_name);
static void crypto_api_generate_random_event(arm_event_t *event);
static void crypto_api_asymmetric_sign_event(arm_event_t *event);
static void crypto_api_asymmetric_verify_event(arm_event_t *event);
static void crypto_api_ecdh_key_agreement_event(arm_event_t *event);
static void crypto_api_free_asymmetric_event_ctx_func(rpc_request_context_t *userdata);
static void crypto_api_free_ecdh_event_ctx_func(rpc_request_context_t *userdata);

EDGE_LOCAL void crypto_api_event_handler(arm_event_t *event)
{
    switch(event->event_id) {
    case CRYPTO_API_EVENT_INIT:
        tr_debug("Crypto RPC API initialized");
        break;
    case CRYPTO_API_EVENT_GET_CERTIFICATE:
        crypto_api_get_kcm_data_event(event, KCM_CERTIFICATE_ITEM, "certificate_name", "certificate_data");
        break;
    case CRYPTO_API_EVENT_GET_PUBLIC_KEY:
        crypto_api_get_kcm_data_event(event, KCM_PUBLIC_KEY_ITEM, "key_name", "key_data");
        break;
    case CRYPTO_API_EVENT_GENERATE_RANDOM:
        crypto_api_generate_random_event(event);
        break;
    case CRYPTO_API_EVENT_ASYMMETRIC_SIGN:
        crypto_api_asymmetric_sign_event(event);
        break;
    case CRYPTO_API_EVENT_ASYMMETRIC_VERIFY:
        crypto_api_asymmetric_verify_event(event);
        break;
    case CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT:
        crypto_api_ecdh_key_agreement_event(event);
        break;
    default:
        break;
    }
}

static int crypto_api_error_predefined(json_t **result, int error_code, const char *error_str)
{
    tr_warn("%s", error_str);
    *result = jsonrpc_error_object_predefined(error_code,
                                              json_string(error_str));
    return JSONRPC_RETURN_CODE_ERROR;
}

static int crypto_api_error(json_t **result, int error_code, const char *error_str)
{
    tr_warn("%s", error_str);
    *result = jsonrpc_error_object(error_code,
                                   pt_api_get_error_message(error_code),
                                   json_string(error_str));
    return JSONRPC_RETURN_CODE_ERROR;
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
             {KCM_CRYPTO_STATUS_ENTROPY_MISSING, "KCM_CRYPTO_STATUS_ENTROPY_MISSING"},
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

static int crypto_api_prepare_and_send_event(json_t *request,
                                             crypto_api_event_e event_type,
                                             uint8_t *event_data_ptr,
                                             int event_data_int,
                                             connection_id_t connection_id)
{
    assert(request != NULL);
    arm_event_t ev = {0};
    crypto_api_event_request_context_t *ctx = protocol_api_prepare_async_ctx(request, connection_id);
    if (ctx == NULL) {
        free(event_data_ptr);
        return -1;
    }

    ctx->connection_id = connection_id;
    ctx->data_ptr = event_data_ptr;
    ctx->data_int = event_data_int;
    ev.event_id = event_type;
    ev.data_ptr = ctx;
    ev.receiver = crypto_api_tasklet_id;
    int rc = eventOS_event_send(&ev);
    if (rc != 0) {
        protocol_api_free_async_ctx_func((rpc_request_context_t *) ctx);
    }
    return rc;
}

static int crypto_api_prepare_and_send_asymmetric_event(json_t *request,
                                                        crypto_api_event_e event_type,
                                                        uint8_t *key_name_ptr,
                                                        uint8_t *hash_ptr,
                                                        uint8_t *signature_ptr,
                                                        connection_id_t connection_id)
{
    assert(request != NULL);
    arm_event_t ev = {0};
    crypto_api_asymmetric_event_request_context_t *ctx = calloc(1, sizeof(crypto_api_asymmetric_event_request_context_t));
    char *request_id = json_dumps(json_object_get(request, "id"), JSON_COMPACT|JSON_ENCODE_ANY);
    if (ctx == NULL || request_id == NULL) {
        free(ctx);
        free(request_id);
        free(key_name_ptr);
        free(hash_ptr);
        free(signature_ptr);
        return -1;
    }

    ctx->request_id = request_id;
    ctx->connection_id = connection_id;
    ctx->key_name_ptr = key_name_ptr;
    ctx->hash_ptr = hash_ptr;
    ctx->signature_ptr = signature_ptr;
    ev.event_id = event_type;
    ev.data_ptr = ctx;
    ev.receiver = crypto_api_tasklet_id;
    int rc = eventOS_event_send(&ev);
    if (rc != 0) {
        crypto_api_free_asymmetric_event_ctx_func((rpc_request_context_t *) ctx);
    }
    return rc;
}
static void crypto_api_free_asymmetric_event_ctx_func(rpc_request_context_t *userdata)
{
    crypto_api_asymmetric_event_request_context_t *ctx = (crypto_api_asymmetric_event_request_context_t *) userdata;
    free(ctx->key_name_ptr);
    free(ctx->hash_ptr);
    free(ctx->signature_ptr);
    free(ctx->request_id);
    free(ctx);
}

static int crypto_api_prepare_and_send_ecdh_event(json_t *request,
                                                  crypto_api_event_e event_type,
                                                  uint8_t *private_key_name,
                                                  uint8_t *peer_public_key,
                                                  connection_id_t connection_id)
{
    assert(request != NULL);
    arm_event_t ev = {0};
    crypto_api_ecdh_event_request_context_t *ctx = calloc(1, sizeof(crypto_api_ecdh_event_request_context_t));
    char *request_id = json_dumps(json_object_get(request, "id"), JSON_COMPACT|JSON_ENCODE_ANY);
    if (ctx == NULL || request_id == NULL) {
        free(ctx);
        free(request_id);
        free(private_key_name);
        free(peer_public_key);
        return -1;
    }

    ctx->request_id = request_id;
    ctx->connection_id = connection_id;
    ctx->private_key_name_ptr = private_key_name;
    ctx->peer_public_key_ptr = peer_public_key;
    ev.event_id = event_type;
    ev.data_ptr = ctx;
    ev.receiver = crypto_api_tasklet_id;
    int rc = eventOS_event_send(&ev);
    if (rc != 0) {
        crypto_api_free_ecdh_event_ctx_func((rpc_request_context_t *) ctx);
    }
    return rc;
}

static void crypto_api_free_ecdh_event_ctx_func(rpc_request_context_t *userdata)
{
    crypto_api_ecdh_event_request_context_t *ctx = (crypto_api_ecdh_event_request_context_t *) userdata;
    free(ctx->private_key_name_ptr);
    free(ctx->peer_public_key_ptr);
    free(ctx->request_id);
    free(ctx);
}

int crypto_api_get_certificate(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Get certificate failed. No request id was given.");
    }


    const char *const_name = json_string_value(json_object_get(json_params, "certificate"));
    if (const_name == NULL) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Get certificate failed. Missing or empty certificate field.");
    }
    uint8_t *name = (uint8_t *) strdup(const_name);

    int status = crypto_api_prepare_and_send_event(request, CRYPTO_API_EVENT_GET_CERTIFICATE, name, 0, connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

int crypto_api_get_public_key(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Get public key failed. No request id was given.");
    }

    const char *const_name = json_string_value(json_object_get(json_params, "key"));
    if (const_name == NULL) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Get public key failed. Missing or empty key field.");
    }

    uint8_t *name = (uint8_t *) strdup(const_name);
    if (name == NULL) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    int status = crypto_api_prepare_and_send_event(request, CRYPTO_API_EVENT_GET_PUBLIC_KEY, name, 0, connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

static void crypto_api_get_kcm_data_event(arm_event_t *event,
                                          kcm_item_type_e item_type,
                                          const char *json_key_name,
                                          const char *json_value_name)
{
    assert(event->data_ptr != NULL);
    crypto_api_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->data_ptr != NULL);

    uint8_t *data_buffer = NULL;
    size_t item_size = 0;
    char *desc = NULL;
    json_t *desc_json = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->request_id);
    json_t *result = NULL;
    kcm_status_e status = kcm_item_get_data_size(ctx->data_ptr,
                                                 strlen((char *) (ctx->data_ptr)),
                                                 item_type,
                                                 &item_size);
    if (status != KCM_STATUS_SUCCESS) {
        if (asprintf(&desc,
                     "Got error when reading item size from KCM, error %d (%s)",
                     status,
                     map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }

    data_buffer = calloc(item_size, sizeof(uint8_t));
    if (data_buffer == NULL) {
        tr_error("Memory allocation error");
        goto send;
    }

    status = kcm_item_get_data(ctx->data_ptr,
                               strlen((char *) (ctx->data_ptr)),
                               item_type,
                               data_buffer,
                               item_size,
                               &item_size);

    if (status != KCM_STATUS_SUCCESS) {
        if (asprintf(&desc,
                     "Got error when reading item from KCM, error %d (%s)",
                     status,
                     map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }


    int encoded_length = apr_base64_encode_len(item_size);
    char *encoded_value = (char *) malloc(encoded_length);
    (void) apr_base64_encode_binary(encoded_value,
                                    (const unsigned char *) data_buffer,
                                    item_size);
    result = json_object();
    json_object_set_new(result, json_key_name, json_string((char *) (ctx->data_ptr)));
    json_object_set_new(result, json_value_name, json_string(encoded_value));
    json_object_set_new(response, "result", result);
    free(encoded_value);

send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        protocol_api_free_async_ctx_func,
                                                        (rpc_request_context_t *) ctx);
    free(data_buffer);
}

int crypto_api_generate_random(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Generate random failed. No request id was given.");
    }

    json_t *size_handle = json_object_get(json_params, "size");
    int size = json_integer_value(size_handle);
    if (size <= 0) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Generate random failed. Missing or invalid size field.");
    }

    int status = crypto_api_prepare_and_send_event(request, CRYPTO_API_EVENT_GENERATE_RANDOM, NULL, size, connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

static void crypto_api_generate_random_event(arm_event_t *event)
{
    assert(event->data_ptr != NULL);
    crypto_api_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->data_int > 0);

    char *desc = NULL;
    json_t *desc_json = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->request_id);
    json_t *result = NULL;

    int encoded_length = apr_base64_encode_len(ctx->data_int);
    uint8_t *random_buffer = (uint8_t*) calloc(1, ctx->data_int);
    uint8_t *encoded_buffer = (uint8_t*) calloc(1, encoded_length);

    if (random_buffer == NULL || encoded_buffer == NULL) {
        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string("Out of memory.")));
        goto send;
    }

    kcm_status_e status = kcm_generate_random(random_buffer, (size_t)ctx->data_int);

    if (status != KCM_STATUS_SUCCESS) {
        if (asprintf(&desc,
                       "Got error when generating random, error %d (%s)",
                       status,
                       map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }

    (void) apr_base64_encode_binary((char *)encoded_buffer,
                                    (const unsigned char *) random_buffer,
                                    ctx->data_int);
    result = json_object();
    json_object_set_new(result, "data", json_string((char *) encoded_buffer));
    json_object_set_new(response, "result", result);

send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        protocol_api_free_async_ctx_func,
                                                        (rpc_request_context_t *) ctx);
    free(random_buffer);
    free(encoded_buffer);
}

int crypto_api_asymmetric_sign(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Asymmetric sign failed. No request id was given.");
    }

    const char *const_name = json_string_value(json_object_get(json_params, "private_key_name"));
    const char *const_hash = json_string_value(json_object_get(json_params, "hash_digest"));
    if (const_name == NULL || const_hash == NULL) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Asymmetric sign failed. Missing or invalid private_key_name or hash_digest field.");
    }

    char *name = strdup(const_name);
    char *hash = strdup(const_hash);
    if (name == NULL || hash == NULL) {
        free(name);
        free(hash);
        return crypto_api_error_predefined(result, JSONRPC_INTERNAL_ERROR, "Out of memory.");
    }

    int status = crypto_api_prepare_and_send_asymmetric_event(request, CRYPTO_API_EVENT_ASYMMETRIC_SIGN, (uint8_t *) name, (uint8_t *) hash, NULL, connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

static void crypto_api_asymmetric_sign_event(arm_event_t *event)
{
    uint8_t signature_buffer[KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE] = {0};
    assert(event->data_ptr != NULL);
    crypto_api_asymmetric_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->key_name_ptr != NULL);
    assert(ctx->hash_ptr != NULL);

    char *desc = NULL;
    json_t *desc_json = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->request_id);
    json_t *result = NULL;

    // Hash pointer is base64 encoded
    int hash_size = apr_base64_decode_len((char *) ctx->hash_ptr);
    uint8_t *hash_decoded = (uint8_t*) calloc(1, hash_size);

    // Allocate buffer for the base64 encoded signature
    uint8_t *sig_encoded = (uint8_t*) calloc(1, apr_base64_encode_len(KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE));

    if (hash_decoded == NULL || sig_encoded == NULL) {
        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string("Out of memory.")));
        goto send;
    }

    hash_size = apr_base64_decode_binary(hash_decoded, (const char*) ctx->hash_ptr);
    size_t sig_max_size = KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE;
    size_t sig_size = 0;
    kcm_status_e status = kcm_asymmetric_sign(ctx->key_name_ptr, strlen((char *) ctx->key_name_ptr), hash_decoded, hash_size, signature_buffer, sig_max_size, &sig_size);

    if (status != KCM_STATUS_SUCCESS) {
        if (asprintf(&desc,
                     "Got error when signing, error %d (%s)",
                     status,
                     map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }

    (void) apr_base64_encode_binary((char *)sig_encoded,
                                    (const unsigned char *) signature_buffer,
                                    sig_size);
    result = json_object();
    json_object_set_new(result, "signature_data", json_string((char *) sig_encoded));
    json_object_set_new(response, "result", result);

send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        crypto_api_free_asymmetric_event_ctx_func,
                                                        (rpc_request_context_t *) ctx);

    free(hash_decoded);
    free(sig_encoded);
}

int crypto_api_asymmetric_verify(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Asymmetric verify failed. No request id was given.");
    }

    const char *const_name = json_string_value(json_object_get(json_params, "public_key_name"));
    const char *const_hash = json_string_value(json_object_get(json_params, "hash_digest"));
    const char *const_sig = json_string_value(json_object_get(json_params, "signature"));
    if (const_name == NULL || const_hash == NULL || const_sig == NULL) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "Asymmetric verify failed. Missing or invalid public_key_name, hash_digest or signature field.");
    }

    char *name = strdup(const_name);
    char *hash = strdup(const_hash);
    char *signature = strdup(const_sig);
    if (name == NULL || hash == NULL || signature == NULL) {
        free(name);
        free(hash);
        free(signature);
        return crypto_api_error_predefined(result, JSONRPC_INTERNAL_ERROR, "Out of memory.");
    }

    int status = crypto_api_prepare_and_send_asymmetric_event(request, CRYPTO_API_EVENT_ASYMMETRIC_VERIFY, (uint8_t *) name, (uint8_t *) hash, (uint8_t *) signature, connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

static void crypto_api_asymmetric_verify_event(arm_event_t *event)
{
    uint8_t signature_decoded[KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE] = {0};
    uint8_t hash_decoded[KCM_SHA256_SIZE] = {0};
    assert(event->data_ptr != NULL);
    crypto_api_asymmetric_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->key_name_ptr != NULL);
    assert(ctx->hash_ptr != NULL);
    assert(ctx->signature_ptr != NULL);

    char *desc = NULL;
    json_t *desc_json = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->request_id);

    // Hash and signature pointers are base64 encoded, first check their lengths are valid
    // and then decode them to stack buffers
    int signature_size = apr_base64_decode_len((const char *) ctx->signature_ptr);
    int hash_size = apr_base64_decode_len((const char *) ctx->hash_ptr);

    if (signature_size > KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE || hash_size > KCM_SHA256_SIZE) {
        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string("Invalid signature or hash length.")));
        goto send;
    }

    signature_size = apr_base64_decode_binary(signature_decoded, (const char*) ctx->signature_ptr);
    hash_size = apr_base64_decode_binary(hash_decoded, (const char*) ctx->hash_ptr);

    kcm_status_e status = kcm_asymmetric_verify(ctx->key_name_ptr,
                                                strlen((char *) ctx->key_name_ptr),
                                                hash_decoded,
                                                hash_size,
                                                signature_decoded,
                                                signature_size);

    if (status != KCM_STATUS_SUCCESS) {
        if (asprintf(&desc,
                     "Got error when verifying, error %d (%s)",
                     status,
                     map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }

    json_object_set_new(response, "result", json_string("ok"));
send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        crypto_api_free_asymmetric_event_ctx_func,
                                                        (rpc_request_context_t *) ctx);
}

int crypto_api_ecdh_key_agreement(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t *) userdata;
    struct connection *connection = jt->connection;

    if (!pt_api_check_service_availability(result)) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    if (!pt_api_check_request_id(jt)) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "ECDH key agreement failed. No request id was given.");
    }

    const char *const_private_key_name = json_string_value(json_object_get(json_params, "private_key_name"));
    const char *const_peer_public_key = json_string_value(json_object_get(json_params, "peer_public_key"));
    if (const_private_key_name == NULL || const_peer_public_key == NULL) {
        return crypto_api_error_predefined(result, JSONRPC_INVALID_PARAMS, "ECDH key agreement failed. Missing or invalid private_key_name or peer_public_key field.");
    }

    char *private_key_name = strdup(const_private_key_name);
    char *peer_public_key = strdup(const_peer_public_key);
    if (private_key_name == NULL || peer_public_key == NULL) {
        free(private_key_name);
        free(peer_public_key);
        return crypto_api_error_predefined(result, JSONRPC_INTERNAL_ERROR, "Out of memory.");
    }

    int status = crypto_api_prepare_and_send_ecdh_event(request,
                                                        CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT,
                                                        (uint8_t *) private_key_name,
                                                        (uint8_t *) peer_public_key,
                                                        connection->id);
    if (status != 0) {
        (void)crypto_api_error(result, PT_API_INTERNAL_ERROR, "Could not send crypto API event.");
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE; // OK so far, but the response is provided later.
}

static void crypto_api_ecdh_key_agreement_event(arm_event_t *event)
{
    uint8_t shared_secret[KCM_EC_SECP256R1_SHARED_SECRET_SIZE] = {0};
    uint8_t shared_secret_encoded[CRYPTO_SHARED_SECRET_BASE64_ENCODE_SIZE] = {0};

    assert(event->data_ptr != NULL);
    crypto_api_ecdh_event_request_context_t *ctx = event->data_ptr;
    assert(ctx->private_key_name_ptr != NULL);
    assert(ctx->peer_public_key_ptr != NULL);

    char *desc = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->request_id);
    json_t *result = NULL;

    // Peer public key is base64 encoded so decode it
    uint8_t *peer_public_key = (uint8_t*) calloc(1, apr_base64_decode_len((const char *) ctx->peer_public_key_ptr));

    if (peer_public_key == NULL) {
        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 json_string("Invalid peer public key field or out of memory.")));
        goto send;
    }

    int peer_key_size = apr_base64_decode_binary(peer_public_key, (const char*) ctx->peer_public_key_ptr);

    size_t shared_secret_size = 0;
    kcm_status_e status = kcm_ecdh_key_agreement(ctx->private_key_name_ptr,
                                                 strlen((char *) ctx->private_key_name_ptr),
                                                 peer_public_key,
                                                 peer_key_size,
                                                 shared_secret,
                                                 KCM_EC_SECP256R1_SHARED_SECRET_SIZE,
                                                 &shared_secret_size);

    if (status != KCM_STATUS_SUCCESS) {
        json_t *desc_json = NULL;
        if (asprintf(&desc,
                     "Got error during ECDH key agreement, error %d (%s)",
                     status,
                     map_kcm_status_to_string(status)) == -1) {
            // Could not create error description, so use generic OOM description.
            desc_json = json_string(error_desc_oom_message);
        }
        else {
            desc_json = json_string(desc);
            free(desc);
        }

        json_object_set_new(response,
                            "error",
                            jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                                 pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                                 desc_json));
        goto send;
    }

    (void) apr_base64_encode_binary((char *)shared_secret_encoded,
                                    (const unsigned char *) shared_secret,
                                    shared_secret_size);

    result = json_object();
    json_object_set_new(result, "shared_secret", json_string((char *) shared_secret_encoded));
    json_object_set_new(response, "result", result);
send:

    (void) edge_server_construct_and_send_response_safe(ctx->connection_id,
                                                        response,
                                                        crypto_api_free_ecdh_event_ctx_func,
                                                        (rpc_request_context_t *) ctx);
    free(peer_public_key);
}
