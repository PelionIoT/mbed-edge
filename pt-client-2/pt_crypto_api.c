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

#include <stdlib.h>
#include <string.h>
#include "ns_list.h"
#include "edge-rpc/rpc.h"
#include "mbed-trace/mbed_trace.h"
#include "common/apr_base64.h"
#include "pt-client-2/pt_crypto_api.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_crypto_api_internal.h"
#define TRACE_GROUP "ptcpto"

EDGE_LOCAL void pt_crypto_success_with_data(json_t *response, void *callback_data, const char *json_key)
{
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    json_t *result_object = NULL;
    json_t *data_object = NULL;
    const char *encoded = NULL;
    unsigned char *plain = NULL;

    if (response == NULL || customer_callback == NULL || json_key == NULL) {
        tr_error("pt_crypto_get_item_success - invalid parameters!");
        return;
    }

    // TODO: Put json key constants into common place
    result_object = json_object_get(response, "result");
    data_object = json_object_get(result_object, json_key);
    encoded = json_string_value(data_object);
    if (data_object == NULL || encoded == NULL) {
        goto fail_cb;
    }

    int plain_len = apr_base64_decode_len(encoded);
    if (plain_len <= 0) {
        goto fail_cb;
    }

    plain = malloc(plain_len);
    plain_len = apr_base64_decode_binary(plain, encoded);

    ((pt_crypto_get_item_success_handler)(customer_callback->success_handler))(customer_callback->connection_id,
                                                                               (const unsigned char*)plain,
                                                                               plain_len,
                                                                               customer_callback->userdata);
    goto exit;
fail_cb:
    ((pt_crypto_get_item_failure_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                               customer_callback->userdata);
exit:
    free(plain);
}

EDGE_LOCAL void pt_crypto_success(json_t *response, void *callback_data)
{
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;

    if (response == NULL || customer_callback == NULL) {
        tr_error("pt_crypto_get_item_success - invalid parameters!");
        return;
    }

    ((pt_crypto_get_item_success_handler)(customer_callback->success_handler))(customer_callback->connection_id,
                                                                               NULL,
                                                                               0,
                                                                               customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_pt_crypto_get_public_key_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_get_public_key_success");
    pt_crypto_success_with_data(response, callback_data, "key_data");
}

EDGE_LOCAL void pt_handle_pt_crypto_get_certificate_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_get_certificate_success");
    pt_crypto_success_with_data(response, callback_data, "certificate_data");
}

EDGE_LOCAL void pt_handle_pt_crypto_generate_random_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_generate_random_success");
    pt_crypto_success_with_data(response, callback_data, "data");
}

EDGE_LOCAL void pt_handle_pt_crypto_asymmetric_sign_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_asymmetric_sign_success");
    pt_crypto_success_with_data(response, callback_data, "signature_data");
}

EDGE_LOCAL void pt_handle_pt_crypto_asymmetric_verify_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_asymmetric_verify_success");
    pt_crypto_success(response, callback_data);
}

EDGE_LOCAL void pt_handle_pt_crypto_ecdh_success(json_t *response, void *callback_data)
{
    tr_info("pt_handle_pt_crypto_ecdh_success");
    pt_crypto_success_with_data(response, callback_data, "shared_secret");
}

EDGE_LOCAL void pt_handle_pt_crypto_get_item_failure(json_t *response, void *callback_data)
{
    tr_err("pt_handle_pt_crypto_get_item_failure");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_crypto_get_item_failure_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                               customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_pt_crypto_failure(json_t *response, void *callback_data)
{
    tr_err("pt_handle_pt_crypto_failure");
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    ((pt_crypto_failure_handler)(customer_callback->failure_handler))(customer_callback->connection_id,
                                                                      json_integer_value(json_object_get(json_object_get(response, "error"), "code")),
                                                                      customer_callback->userdata);
}

pt_status_t pt_crypto_get_certificate(const connection_id_t connection_id,
                                      const char *name,
                                      pt_crypto_get_item_success_handler success_handler,
                                      pt_crypto_get_item_failure_handler failure_handler,
                                      void *userdata)
{
    if (name == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_get_certificate");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_name = json_string(name);
    if (message == NULL || params == NULL || customer_callback == NULL || json_name == NULL) {
        json_decref(message);
        json_decref(json_name);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "certificate", json_name);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_get_certificate_success,
                                               pt_handle_pt_crypto_get_item_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

pt_status_t pt_crypto_get_public_key(const connection_id_t connection_id,
                                     const char *name,
                                     pt_crypto_get_item_success_handler success_handler,
                                     pt_crypto_get_item_failure_handler failure_handler,
                                     void *userdata)
{
    if (name == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_get_public_key");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_name = json_string(name);
    if (message == NULL || params == NULL || customer_callback == NULL || json_name == NULL) {
        json_decref(message);
        json_decref(json_name);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "key", json_name);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_get_public_key_success,
                                               pt_handle_pt_crypto_get_item_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

pt_status_t pt_crypto_generate_random(const connection_id_t connection_id,
                                      const size_t size,
                                      pt_crypto_success_handler success_handler,
                                      pt_crypto_failure_handler failure_handler,
                                      void *userdata)
{
    if (size == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_generate_random");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_size = json_integer(size);
    if (message == NULL || params == NULL || customer_callback == NULL || json_size == NULL) {
        json_decref(message);
        json_decref(json_size);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "size", json_size);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_generate_random_success,
                                               pt_handle_pt_crypto_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

pt_status_t pt_crypto_asymmetric_sign(const connection_id_t connection_id,
                                      const char *private_key_name,
                                      const char *hash_digest,
                                      const size_t hash_digest_size,
                                      pt_crypto_success_handler success_handler,
                                      pt_crypto_failure_handler failure_handler,
                                      void *userdata)
{
    if (private_key_name == NULL || hash_digest == NULL || hash_digest_size == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_asymmetric_sign");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_hash = NULL;
    char *hash_encoded = (char *) malloc(apr_base64_encode_len(hash_digest_size));
    if (hash_encoded != NULL) {
        (void)apr_base64_encode_binary(hash_encoded, (const uint8_t *) hash_digest, hash_digest_size);
        json_hash = json_string(hash_encoded);
        free(hash_encoded);
    }
    json_t *json_private_key = json_string(private_key_name);

    if (message == NULL || params == NULL || customer_callback == NULL || json_private_key == NULL || json_hash == NULL) {
        json_decref(message);
        json_decref(json_private_key);
        json_decref(json_hash);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    json_object_set_new(params, "private_key_name", json_private_key);
    json_object_set_new(params, "hash_digest", json_hash);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_asymmetric_sign_success,
                                               pt_handle_pt_crypto_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}
pt_status_t pt_crypto_asymmetric_verify(const connection_id_t connection_id,
                                        const char *public_key_name,
                                        const char *hash_digest,
                                        const size_t hash_digest_size,
                                        const char *signature,
                                        const size_t signature_size,
                                        pt_crypto_success_handler success_handler,
                                        pt_crypto_failure_handler failure_handler,
                                        void *userdata)
{
    if (public_key_name == NULL || hash_digest == NULL || hash_digest_size == 0 || signature == NULL || signature_size == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_asymmetric_verify");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_hash = NULL;
    char *hash_encoded = (char *) malloc(apr_base64_encode_len(hash_digest_size));
    if (hash_encoded != NULL) {
        (void)apr_base64_encode_binary(hash_encoded, (const uint8_t *) hash_digest, hash_digest_size);
        json_hash = json_string(hash_encoded);
        free(hash_encoded);
    }

    json_t *json_signature = NULL;
    char *signature_encoded = (char *) malloc(apr_base64_encode_len(signature_size));
    if (signature_encoded != NULL) {
        (void)apr_base64_encode_binary(signature_encoded, (const uint8_t *) signature, signature_size);
        json_signature = json_string(signature_encoded);
        free(signature_encoded);
    }

    json_t *json_public_key = json_string(public_key_name);

    if (message == NULL || params == NULL || customer_callback == NULL ||
        json_public_key == NULL || json_hash == NULL || json_signature == NULL) {
        json_decref(message);
        json_decref(json_public_key);
        json_decref(json_hash);
        json_decref(json_signature);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    json_object_set_new(params, "public_key_name", json_public_key);
    json_object_set_new(params, "hash_digest", json_hash);
    json_object_set_new(params, "signature", json_signature);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_asymmetric_verify_success,
                                               pt_handle_pt_crypto_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}
pt_status_t pt_crypto_ecdh_key_agreement(const connection_id_t connection_id,
                                         const char *private_key_name,
                                         const char *peer_public_key,
                                         const size_t peer_public_key_size,
                                         pt_crypto_success_handler success_handler,
                                         pt_crypto_failure_handler failure_handler,
                                         void *userdata)
{
    if (private_key_name == NULL || peer_public_key == NULL || peer_public_key_size == 0) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    json_t *message = allocate_base_request("crypto_ecdh_key_agreement");
    json_t *params = json_object_get(message, "params");
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);

    json_t *json_peer_key = NULL;
    char *peer_key_encoded = (char *) malloc(apr_base64_encode_len(peer_public_key_size));
    if (peer_key_encoded != NULL) {
        (void)apr_base64_encode_binary(peer_key_encoded, (const uint8_t *) peer_public_key, peer_public_key_size);
        json_peer_key = json_string(peer_key_encoded);
        free(peer_key_encoded);
    }
    json_t *json_private_key = json_string(private_key_name);

    if (message == NULL || params == NULL || customer_callback == NULL || json_private_key == NULL || json_peer_key == NULL) {
        json_decref(message);
        json_decref(json_private_key);
        json_decref(json_peer_key);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    json_object_set_new(params, "private_key_name", json_private_key);
    json_object_set_new(params, "peer_public_key", json_peer_key);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_pt_crypto_ecdh_success,
                                               pt_handle_pt_crypto_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}
