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

#include "pt-client-2/pt_certificate_api.h"
#include "ns_list.h"
#include <stdlib.h>
#include "pt-client-2/pt_api_internal.h"
#include "edge-rpc/rpc.h"
#include <string.h>
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "ptcert"

typedef struct pt_certificate_item {
    ns_list_link_t link;
    char *name;
} pt_certificate_item_t;

typedef NS_LIST_HEAD(pt_certificate_item_t, link) pt_certificate_items_t;

struct pt_certificate_list {
    pt_certificate_items_t list;
};

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

