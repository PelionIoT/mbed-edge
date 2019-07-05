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
#define _GNU_SOURCE 1 // needed for strndup
#endif

#include "edge-rpc/rpc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "ns_list.h"
#include <jansson.h>

#include "mbed-trace/mbed_trace.h"
#include "common/edge_time.h"
#include "common/pt_api_error_codes.h"

#define TRACE_GROUP "rpc"

/**
 * Defines warning threshold of the user supplied callback processing time
 * In milliseconds
 */
#define WARN_CALLBACK_RUNTIME 500

generate_msg_id g_generate_msg_id;

typedef struct message {
    json_t *json_message;
    char *id;
    rpc_request_context_t *request_context;
    struct connection *connection;
    ns_list_link_t link;
    rpc_response_handler success_handler;
    rpc_response_handler failure_handler;
    rpc_free_func free_func;
    uint64_t creation_timestamp_in_ms;
} message_t;

edge_mutex_t rpc_mutex;

static message_t *_remove_message_for_connection_and_id(struct connection *connection,
                                                        const char *message_id,
                                                        bool acquire_mutex);

void rpc_init()
{
    int32_t result = edge_mutex_init(&rpc_mutex, PTHREAD_MUTEX_ERRORCHECK);
    assert(0 == result);
}

void rpc_deinit()
{
    int32_t result = edge_mutex_destroy(&rpc_mutex);
    assert(0 == result);
}

static void rpc_mutex_wait()
{
    int32_t result = edge_mutex_lock(&rpc_mutex);
    assert(0 == result);
}

static void rpc_mutex_release()
{
    int32_t result = edge_mutex_unlock(&rpc_mutex);
    assert(0 == result);
}

/*
 * List to contain sent messages
 */
static NS_LIST_DEFINE(messages, message_t, link);

int rpc_message_list_size()
{
    rpc_mutex_wait();
    int count = ns_list_count(&messages);
    rpc_mutex_release();
    return count;
}

bool rpc_message_list_is_empty()
{
    rpc_mutex_wait();
    bool is_empty = ns_list_is_empty(&messages);
    rpc_mutex_release();
    return is_empty;
}

json_t* allocate_base_request(const char* method)
{
    json_t *msg = json_object();
    json_t *params = json_object();
    json_object_set_new(msg, "jsonrpc", json_string("2.0"));
    json_object_set_new(msg, "method", json_string(method));
    json_object_set_new(msg, "params", params);

    return msg;
}

static message_t *alloc_message(json_t *json_message,
                                rpc_response_handler success_handler,
                                rpc_response_handler failure_handler,
                                rpc_free_func free_func,
                                rpc_request_context_t *request_context,
                                struct connection *connection)
{
    if (request_context == NULL) {
        tr_warn("No request context for RPC request.");
    }
    message_t *entry = calloc(1, sizeof(message_t));
    if (entry == NULL) {
        tr_err("Error: Out of memory.");
        return NULL;
    }
    entry->creation_timestamp_in_ms = edgetime_get_monotonic_in_ms();
    entry->json_message = json_message;
    entry->success_handler = success_handler;
    entry->failure_handler = failure_handler;
    if (!free_func) {
        tr_warn("NOTE! No free_func was given to deallocate the request_context parameter.");
    }
    else {
        entry->free_func = free_func;
    }
    entry->request_context = request_context;
    entry->connection = connection;
    return entry;
}

void rpc_dealloc_message_entry(void *message_entry)
{
    message_t *message = (message_t *) message_entry;
    if (message) {
        json_decref(message->json_message);
        /* Free the customer callbacks */
        if (message->free_func) {
            message->free_func(message->request_context);
        }
        else {
            tr_warn("NOTE! 'free_func' was NULL therefore deallocation for request_context is impossible.");
        }
        free(message);
    }
}

struct json_message_t* alloc_json_message_t(const char* data, size_t len, struct connection *connection)
{
    struct json_message_t *msg = malloc(sizeof(struct json_message_t));
    if (NULL == msg) {
        tr_err("Cannot allocate msg in alloc_json_message_t");
        return NULL;
    }
    msg->data = strndup(data, len);
    if (NULL == msg->data) {
        tr_err("Cannot allocate msg->data in allloc_json_message_t");
        free(msg);
        return NULL;
    }
    msg->len = len;
    msg->connection = connection;
    return msg;
}

void deallocate_json_message_t(struct json_message_t *msg)
{
    if (msg && msg->data) {
        free(msg->data);
    }
    free(msg);
}

void rpc_set_generate_msg_id(generate_msg_id generate_msg_id)
{
    g_generate_msg_id = generate_msg_id;
}

int rpc_construct_message(json_t *message,
                          rpc_response_handler success_handler,
                          rpc_response_handler failure_handler,
                          rpc_free_func free_func,
                          rpc_request_context_t *request_context,
                          struct connection *connection,
                          void **returned_msg_entry,
                          char **data,
                          size_t *data_len,
                          char **message_id)
{
    *returned_msg_entry = NULL;
    if (message == NULL) {
        tr_warn("A null message pointer was passed to rpc_construct_message.");
        return 1;
    }

    if (data == NULL || message_id == NULL) {
        tr_warn("A null data or message id output param was passed to rpc_construct_message.");
        return 1;
    }

    *message_id = g_generate_msg_id();
    json_object_set_new(message, "id", json_string(*message_id));

    *data_len = json_dumpb(message, NULL, 0, JSON_COMPACT | JSON_SORT_KEYS);

    *data = (char *) malloc(*data_len);

    if (*data != NULL) {
        *data_len = json_dumpb(message, *data, *data_len, JSON_COMPACT | JSON_SORT_KEYS);
        message_t *msg_entry = alloc_message(message,
                                             success_handler,
                                             failure_handler,
                                             free_func,
                                             request_context,
                                             connection);
        if (NULL == msg_entry) {
            // FIXME: handle error
            tr_err("Error in adding the request to the request list.");
            free(*data);
            *data = NULL;
            *data_len = 0;
            return 1;
        }
        *returned_msg_entry = msg_entry;
        return 0;
    } else {
        *data_len = 0;
        // FIXME: handle error
        tr_err("Error allocating buffer for the RPC message.");
        return 1;
    }
}

int rpc_construct_response(json_t *response, char **data, size_t *data_len)
{
    if (response == NULL) {
        tr_warn("A null response pointer was passed to rpc_construct_response.");
        return 1;
    }

    if (data == NULL || json_object_get(response, "id") == NULL) {
        tr_warn("A null data or response id output param was passed to rpc_construct_response.");
        return 1;
    }

    *data_len = json_dumpb(response, NULL, 0, JSON_COMPACT | JSON_SORT_KEYS);

    *data = (char *) malloc(*data_len);
    if (NULL == *data) {
        tr_err("Cannot allocate *data in rpc_construct_response");
        return 1;
    }
    *data_len = json_dumpb(response, *data, *data_len, JSON_COMPACT | JSON_SORT_KEYS);
    return 0;
}

int32_t rpc_construct_and_send_message(struct connection *connection,
                                       json_t *message,
                                       rpc_response_handler success_handler,
                                       rpc_response_handler failure_handler,
                                       rpc_free_func free_func,
                                       rpc_request_context_t *customer_callback_ctx,
                                       write_func write_function)
{
    void *message_entry;
    char *data;
    char *message_id;
    size_t data_len;
    int rc = rpc_construct_message(message,
                                   success_handler,
                                   failure_handler,
                                   free_func,
                                   customer_callback_ctx,
                                   connection,
                                   &message_entry,
                                   &data,
                                   &data_len,
                                   &message_id);

    if (rc == 1 || data == NULL) {
        json_decref(message);
        free_func(customer_callback_ctx);
        return -1;
    }

    /*
     * Add message to list before writing to socket.
     * There is a condition when other end may respond back before
     * having the message in the message list.
     */
    rpc_add_message_entry_to_list(message_entry);
    int32_t ret = write_function(connection, data, data_len);
    if (ret != 0) {
        tr_err("write_function returned %d", ret);
        message_t *found = _remove_message_for_connection_and_id(connection, (const char*)message_id, true /* acquire_mutex */);
        rpc_dealloc_message_entry(found);
        return -2; // the message_couldn't be sent
    }
    free(message_id);
    return ret;
}

int32_t rpc_construct_and_send_response(struct connection *connection,
                                        json_t *response,
                                        rpc_free_func free_func,
                                        rpc_request_context_t *customer_callback_ctx,
                                        write_func write_function)
{
    char *data;
    size_t data_len;
    int32_t return_code = 0;
    int rc = rpc_construct_response(response, &data, &data_len);
    json_decref(response);

    if (rc == 1 || data == NULL) {
        return_code = -1;
    } else if (0 != write_function(connection, data, data_len)) {
        return_code = -2;
    }
    if (free_func) {
        free_func(customer_callback_ctx);
    }

    return return_code;
}

void rpc_add_message_entry_to_list(void *message_entry)
{
    if (message_entry) {
#if MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG
        message_t *msg = (message_t *) message_entry;
        json_t *id_obj = json_object_get(msg->json_message, "id");
        char *id_string = json_dumps(id_obj, JSON_COMPACT|JSON_ENCODE_ANY);
        tr_debug("rpc_add_message_entry_to_list, connection: %p id : %s", msg->connection, id_string);
        free(id_string);
#endif
        rpc_mutex_wait();
        ns_list_add_to_end(&messages, (message_t *) message_entry);
        rpc_mutex_release();
    }
}

static message_t *_remove_message_for_connection_and_id(struct connection *connection,
                                                        const char *message_id,
                                                        bool acquire_mutex)
{
    message_t *found = NULL;
    tr_debug("_remove_message_for_connection_and_id connection: %p id: %s", connection, message_id);
    if (acquire_mutex) {
        rpc_mutex_wait();
    }
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        json_t *id_obj = json_object_get(cur->json_message, "id");
        assert(id_obj != NULL);
        char *id_string = json_dumps(id_obj, JSON_COMPACT|JSON_ENCODE_ANY);
        if (cur->connection == connection && id_string != NULL && strncmp(id_string, message_id, strlen(message_id)) == 0) {
            found = cur;
            ns_list_remove(&messages, found);
            free(id_string);
            break;
        }
        free(id_string);
    }
    if (acquire_mutex) {
        rpc_mutex_release();
    }
    return found;
}

static message_t *remove_message_for_response(struct connection *connection,
                                              json_t *response,
                                              char **response_id,
                                              bool acquire_mutex)
{
    json_t *response_id_obj = json_object_get(response, "id");
    if (response_id_obj == NULL) {
        tr_error("Can't find id in response");
        return NULL;
    }

    *response_id = json_dumps(response_id_obj, JSON_COMPACT|JSON_ENCODE_ANY);
    if (response_id == NULL) {
        tr_error("Can't allocate response id object");
        return NULL;
    }

    return _remove_message_for_connection_and_id(connection, (const char*)*response_id, acquire_mutex);
}

static int handle_response_common(struct connection *connection, json_t *response, bool acquire_mutex)
{
    int rc;
    char *response_id = NULL;
    message_t *found;

    found = remove_message_for_response(connection, response, &response_id, acquire_mutex);
    if (found != NULL) {
        json_t *result_obj = json_object_get(response, "result");

        /* Get the start clock units */
        uint64_t begin_time = edgetime_get_monotonic_in_ms();

        // FIXME: Check that result contains ok
        if (result_obj != NULL) {
            found->success_handler(response, found->request_context);
            rc = 0;
        } else {
            // Must be error if there is no "result"
            found->failure_handler(response, found->request_context);
            rc = 1;
        }

        /* Get the end clock units */
        uint64_t end_time = edgetime_get_monotonic_in_ms();

        /* This will convert the clock units to milliseconds, this measures cpu time
         * The measured runtime contains the time consumed in internal callbacks and
         * customer callbacks.
         */
        double callback_time = end_time - begin_time;
        tr_debug("Callback time %f ms.", callback_time);
        if (callback_time >= WARN_CALLBACK_RUNTIME) {
            tr_warn("Callback processing took more than %d milliseconds to run, actual call took %f ms.", WARN_CALLBACK_RUNTIME, callback_time);
        }
        rpc_dealloc_message_entry(found);
    } else {
        tr_err("Did not find any matching request for the response with id: %s.", response_id);
        rc = -1;
    }
    free(response_id);
    return rc;
}

static int handle_response(struct connection *connection, json_t *response)
{
    return handle_response_common(connection, response, true /* acquire_mutex */);
}

static int handle_response_without_mutex(struct connection *connection, json_t *response)
{
    return handle_response_common(connection, response, false /* acquire_mutex */);
}

int rpc_handle_message(const char *data,
                       size_t len,
                       struct connection *connection,
                       struct jsonrpc_method_entry_t *method_table,
                       write_func write_function,
                       bool *protocol_error,
                       bool mutex_acquired)
{
    *protocol_error = false;
    jsonrpc_response_handler response_handler = handle_response;

    if (mutex_acquired) {
        response_handler = handle_response_without_mutex;
    }
    struct json_message_t *json_message = alloc_json_message_t(data, len, connection);
    if (!json_message) {
        tr_err("Cannot allocate json_message in rpc_handle_message");
        return 1;
    }
    jsonrpc_handler_e rc;
    char *response = jsonrpc_handler(data, len, method_table, response_handler, json_message, &rc);

    switch (rc) {
        case JSONRPC_HANDLER_REQUEST_NOT_MATCHED:
        case JSONRPC_HANDLER_JSON_PARSE_ERROR: {
            *protocol_error = true;
            break;
        }
        default:
            break;
    }

    deallocate_json_message_t(json_message);
    if (response == NULL) {
        // When response is received in rpc_handle_message, there's no response for that.
        if (rc == JSONRPC_HANDLER_OK) {
            return 0;
        }
        return 1;
    }
    return write_function(connection, response, strlen(response));
}

static void send_error_response(json_t *json_id, json_t *result, struct connection *connection)
{
    json_t *json_response = jsonrpc_error_response(json_id, result);
    size_t size = json_dumpb(json_response, NULL, 0, JSON_COMPACT | JSON_SORT_KEYS);
    if (size > 0) {
        char *buf = malloc(size);
        if (buf) {
            size = json_dumpb(json_response, buf, size, JSON_COMPACT | JSON_SORT_KEYS);
            bool protocol_error = false;
            rpc_handle_message(buf, size, connection, NULL, NULL, &protocol_error, true /* mutex_acquired */);
        }
        free(buf);
    }
    json_decref(json_response);
}

void rpc_timeout_unresponded_messages(int32_t max_response_time_ms)
{
    uint64_t current_time = edgetime_get_monotonic_in_ms();
    rpc_mutex_wait();
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        if (current_time - cur->creation_timestamp_in_ms >= max_response_time_ms) {
            char *desc = NULL;
            if (asprintf(&desc, "Timeout response with timeout threshold %d ms", max_response_time_ms) >= 0) {
                json_t *json_id;
                json_t *json_params;
                const char *str_method;

                json_t *json_response = jsonrpc_validate_request(cur->json_message,
                                                                 &str_method,
                                                                 &json_params,
                                                                 &json_id);
                // The request should still be valid.
                assert(NULL == json_response);
                assert(NULL != json_id);
                assert(NULL != str_method);

                json_t *result = jsonrpc_error_object(PT_API_REQUEST_TIMEOUT,
                                                      pt_api_get_error_message(PT_API_REQUEST_TIMEOUT),
                                                      json_string(desc));
                char *id_string = json_dumps(json_id, JSON_COMPACT|JSON_ENCODE_ANY);
                tr_warn("Timeout for request id: %s", id_string);
                send_error_response(json_id, result, cur->connection);
                free(id_string);
                free(desc);
            }
        }
    }
    rpc_mutex_release();
}

void rpc_remote_disconnected(struct connection *connection)
{
    rpc_mutex_wait();
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        if (cur->connection == connection) {
            json_t *json_id;
            json_t *json_params;
            const char *str_method;

            json_t *json_response = jsonrpc_validate_request(cur->json_message, &str_method, &json_params, &json_id);
            // The request should still be valid.
            assert(NULL == json_response);
            assert(NULL != json_id);
            assert(NULL != str_method);

            json_t *result = jsonrpc_error_object(PT_API_REMOTE_DISCONNECTED,
                                                  pt_api_get_error_message(PT_API_REMOTE_DISCONNECTED),
                                                  json_string("Remote disconnected"));
            tr_warn("Remote disconnected, request id: %s", json_string_value(json_id));
            send_error_response(json_id, result, cur->connection);
        }
    }
    rpc_mutex_release();
}

void rpc_destroy_messages()
{
    int32_t count = 0;
    rpc_mutex_wait();
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        ns_list_remove(&messages, cur);
        rpc_dealloc_message_entry(cur);
        count ++;
    }
    rpc_mutex_release();
    tr_warn("Destroyed %d (unhandled) messages.", count);
}
