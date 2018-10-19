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

#include "edge-rpc/rpc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include "ns_list.h"
#include <jansson.h>

#include "mbed-trace/mbed_trace.h"
#include "common/edge_time.h"
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
    void *request_context;
    ns_list_link_t link;
    rpc_response_handler success_handler;
    rpc_response_handler failure_handler;
    rpc_free_func free_func;
} message_t;

/*
 * List to contain sent messages
 */
static NS_LIST_DEFINE(messages, message_t, link);

int rpc_message_list_size()
{
    return ns_list_count(&messages);
}

bool rpc_message_list_is_empty()
{
    return ns_list_is_empty(&messages);
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

message_t* alloc_message(json_t *json_message, rpc_response_handler success_handler,
                         rpc_response_handler failure_handler,
                         rpc_free_func free_func,
                         void *request_context)
{
    message_t *entry = calloc(1, sizeof(message_t));
    if (entry == NULL) {
        // FIXME: exit process?
        tr_err("Error could not allocate message struct.");
    }
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
        tr_err("Cannot allocate msg in allloc_json_message_t");
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
                          void *request_context,
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
        message_t *msg_entry = alloc_message(message, success_handler, failure_handler, free_func, request_context);
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
    const char *message_id = json_string_value(json_object_get(response, "id"));

    if (data == NULL || message_id == NULL) {
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
                                       void *customer_callback,
                                       write_func write_function)
{
    void *message_entry;
    char *data;
    char *message_id;
    size_t data_len;
    int rc = rpc_construct_message(message, success_handler, failure_handler,
                                   free_func, customer_callback, &message_entry,
                                   &data, &data_len, &message_id);

    if (rc == 1 || data == NULL) {
        json_decref(message);
        free_func(customer_callback);
        return -1;
    }

    /*
     * Add message to list before writing to socket.
     * There is a condition when other end may respond back before
     * having the message in the message list.
     */
    rpc_add_message_entry_to_list(message_entry);
    write_function(connection, data, data_len);
    free(message_id);

    return 0;
}

int32_t rpc_construct_and_send_response(struct connection *connection,
                                        json_t *response,
                                        rpc_free_func free_func,
                                        void *customer_callback_ctx,
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
        ns_list_add_to_end(&messages, (message_t *) message_entry);
    }
}

static message_t *_remove_message_for_id(const char *message_id)
{
    message_t *found = NULL;
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        json_t *id_obj = json_object_get(cur->json_message, "id");
        assert(id_obj != NULL);
        if (strncmp(json_string_value(id_obj), message_id, strlen(message_id)) == 0) {
            found = cur;
            ns_list_remove(&messages, found);
            break;
        }
    }
    return found;
}

static message_t *remove_message_for_response(json_t *response, const char **response_id)
{
  json_t *response_id_obj = json_object_get(response, "id");
  if (response_id_obj == NULL) {
      // FIXME: No id in response, handle as failure
      tr_error("Can't find id in response");
      return NULL;
  }

  *response_id = json_string_value(response_id_obj);
  return _remove_message_for_id(*response_id);
}

void remove_message_for_id(const char *message_id)
{
    (void *) _remove_message_for_id(message_id);
}


int handle_response(json_t *response)
{
    int rc = 1;
    const char *response_id = NULL;
    message_t *found = NULL;

    found = remove_message_for_response(response, &response_id);
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

    } else {
        tr_warn("Did not find any matching request for the response with id: %s.", response_id);
        rc = 1;
    }
    if (found) {
        rpc_dealloc_message_entry(found);
    }
    return rc;
}

int rpc_handle_message(const char *data,
                       size_t len,
                       struct connection *connection,
                       struct jsonrpc_method_entry_t *method_table,
                       write_func write_function,
                       bool *protocol_error)
{
    *protocol_error = false;
    struct json_message_t *json_message = alloc_json_message_t(data, len, connection);
    if (!json_message) {
        tr_err("Cannot allocate json_message in rpc_handle_message");
        return 1;
    }

    char *response = jsonrpc_handler(data, len, method_table, handle_response, json_message, protocol_error);

    deallocate_json_message_t(json_message);
    if (response == NULL) {
        return 1;

    }
    int rc = write_function(connection, response, strlen(response));
    return rc;
}

void rpc_destroy_messages()
{
    int32_t count = 0;
    ns_list_foreach_safe(message_t, cur, &messages)
    {
        ns_list_remove(&messages, cur);
        rpc_dealloc_message_entry(cur);
        count ++;
    }
    tr_warn("Destroyed %d (unhandled) messages.", count);
}
