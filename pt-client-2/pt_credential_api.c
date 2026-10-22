/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "pt-client-2/pt_credential_api.h"
#include "pt-client-2/pt_api_internal.h"
#include "edge-rpc/rpc.h"
#include "common/apr_base64.h"

static void failed(json_t *response, void *data)
{
    pt_customer_callback_t *callback = data;
    json_t *code = json_object_get(json_object_get(response, "error"), "code");
    ((pt_crypto_failure_handler)callback->failure_handler)(callback->connection_id,
        json_is_integer(code) ? (int)json_integer_value(code) : -32043, callback->userdata);
}

static void received(json_t *response, void *data, bool challenge)
{
    pt_customer_callback_t *callback = data;
    json_t *result = json_object_get(response, "result");
    json_t *value = json_object_get(result, challenge ? "challenge" : "envelope");
    const char *text = json_string_value(value);
    uint8_t *packet = NULL; int length = 0;
    bool ok = text && strlen(text) == json_string_length(value) && strlen(text) <= 8192 &&
        (!challenge || json_integer_value(json_object_get(result, "version")) == 1);
    if (ok) {
        packet = malloc((size_t)apr_base64_decode_len(text));
        ok = packet != NULL;
    }
    if (ok) {
        length = apr_base64_decode_binary(packet, text);
        ok = challenge ? length == 32 : length >= 28 && length <= 6144;
    }
    if (ok) ((pt_crypto_success_handler)callback->success_handler)(callback->connection_id, packet, (size_t)length, callback->userdata);
    else ((pt_crypto_failure_handler)callback->failure_handler)(callback->connection_id, -32043, callback->userdata);
    free(packet);
}
static void opened(json_t *response, void *data) { received(response, data, true); }
static void answered(json_t *response, void *data) { received(response, data, false); }

static pt_status_t send_request(connection_id_t connection, json_t *message, bool open,
    pt_crypto_success_handler success, pt_crypto_failure_handler failure, void *userdata)
{
    if (!success || !failure) { json_decref(message); return PT_STATUS_INVALID_PARAMETERS; }
    pt_customer_callback_t *callback = allocate_customer_callback(connection,
        (pt_response_handler)success, (pt_response_handler)failure, userdata);
    if (!message || !callback) {
        json_decref(message);
        if (callback) customer_callback_free_func((rpc_request_context_t *)callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return construct_and_send_outgoing_message(connection, message, open ? opened : answered, failed,
        (rpc_free_func)customer_callback_free_func, PT_CUSTOMER_CALLBACK_T, callback);
}

pt_status_t pt_credential_open(connection_id_t connection,
    pt_crypto_success_handler success, pt_crypto_failure_handler failure, void *userdata)
{
    return send_request(connection, allocate_base_request("credential_open"), true, success, failure, userdata);
}

pt_status_t pt_credential_request(connection_id_t connection, const char *namespace_name,
    uint64_t sequence, const uint8_t *envelope, size_t size,
    pt_crypto_success_handler success, pt_crypto_failure_handler failure, void *userdata)
{
    if (!namespace_name || !*namespace_name || strlen(namespace_name) > 32 || sequence >= INT64_MAX ||
        !envelope || size < 28 || size > 6144) return PT_STATUS_INVALID_PARAMETERS;
    json_t *message = allocate_base_request("credential_request");
    char *text = malloc((size_t)apr_base64_encode_len((int)size));
    if (!message || !text) { json_decref(message); free(text); return PT_STATUS_ALLOCATION_FAIL; }
    apr_base64_encode_binary(text, envelope, (int)size);
    json_t *params = json_object_get(message, "params");
    bool ok = json_object_set_new(params, "namespace", json_string(namespace_name)) == 0 &&
        json_object_set_new(params, "sequence", json_integer((json_int_t)sequence)) == 0 &&
        json_object_set_new(params, "envelope", json_string(text)) == 0;
    free(text);
    if (!ok) { json_decref(message); return PT_STATUS_ALLOCATION_FAIL; }
    return send_request(connection, message, false, success, failure, userdata);
}
