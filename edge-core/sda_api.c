#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <assert.h>

#include "edge-core/sda_api_internal.h"
#include "edge-client/sda_operation.h"
#include "jsonrpc/jsonrpc.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "SDAC"
struct jsonrpc_method_entry_t sda_method_table[] = {
    { "sda_request", sda_request, "o" },
    {NULL, NULL}
};

bool sda_api_check_request_id(struct json_message_t *jt)
/**
 * \brief Checks if the request id is in the JSON request.
 * \return true  - request id is found
 *         false - request id is missing
 */
{
    json_error_t error;
    json_t *full_request = json_loadb(jt->data, jt->len, 0, &error);
    json_t *id_obj = json_object_get(full_request, "id");
    json_decref(full_request);

    if (id_obj == NULL) {
        return false;
    }
    return true;
}


// process the sda request 
int sda_request(json_t *request, json_t *json_params, json_t **result, void *userdata) {
    uint16_t response_max_size = 2000;
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;

    if (!sda_api_check_request_id(jt)) {
        tr_warn("EST enrollment request failed. No request id was given.");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("EST enrollment request renewal failed. No request id was given."));
        return JSONRPC_RETURN_CODE_ERROR;
    }
    
    uint8_t response[2000] = {0};

    uint32_t sda_response_size = 0;
    json_t *request_handle = json_object_get(json_params, "request");
    if (request_handle == NULL) {
        *result = jsonrpc_error_object(
                JSONRPC_INVALID_PARAMS,
                "Invalid params. Missing 'request', field from request.",
                NULL);
        return JSONRPC_RETURN_CODE_ERROR;
    }

    const char *request_encoded = json_string_value(request_handle);
    if (request_encoded == NULL) {
        return JSONRPC_RETURN_CODE_ERROR;
    }
    uint32_t req_len = apr_base64_decode_len(request_encoded);
    uint8_t *sda_request = malloc(req_len * sizeof(uint8_t));
    if (NULL == sda_request) {
        tr_error("request is null");
        return JSONRPC_RETURN_CODE_ERROR;
    }
    uint32_t r_req_len = apr_base64_decode_binary(sda_request, request_encoded);
    uint16_t res_size = 0;
    sda_protocol_error_t err = sda_client_request(sda_request, response, response_max_size, &res_size);
    if(err != PT_ERR_OK) {
        char err_msg[50] = "";
        sprintf(err_msg, "Can not process request, reason: %d", err);
        *result = jsonrpc_error_object(
                    JSONRPC_INVALID_PARAMS,
                    err_msg,
                    NULL);
        free(sda_request);
        sda_request = NULL;
        return JSONRPC_RETURN_CODE_ERROR;
    }
    free(sda_request);
    sda_request = NULL;
    size_t enc_res_size = 0;
    unsigned char *enc_response = NULL;

    if (0 != mbedtls_base64_encode(enc_response, enc_res_size, &enc_res_size, response, res_size)) {
        tr_error("Could not encode sda response to base64.");
        return JSONRPC_RETURN_CODE_ERROR;
    }
    json_t *json_result = json_object();
    json_object_set_new(json_result, "response", json_string(enc_response));
    *result = json_result;
    *result = json_string("ok");
    return JSONRPC_RETURN_CODE_SUCCESS;

}