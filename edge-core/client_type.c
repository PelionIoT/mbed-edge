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

#include <stdlib.h>
#include "edge-core/client_type.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-core/mgmt_api_internal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clienttype"

client_data_t *edge_core_create_client(enum client_type client_type)
{
    client_data_t *client_data = calloc(1, sizeof(client_data_t));
    if (!client_data) {
        tr_err("Could not allocate memory for client_data_t structure.");
        return NULL;
    }
    // Set the id to invalid
    client_data->id = -1;
    client_data->name = NULL;
    client_data->registered = false;
    ns_list_init(&client_data->certificate_list);

    if (client_type == PT) {
        client_data->_pre_destroy_client_data = edge_core_protocol_api_client_data_destroy;
        client_data->method_table = method_table;
    } else if (client_type == MGMT) {
        client_data->_pre_destroy_client_data = NULL;
        client_data->method_table = mgmt_api_method_table;
    } else {
        tr_warn("No destroy function for client type.");
    }

    return client_data;
}

void edge_core_client_data_destroy(client_data_t **client_data)
{
    if(*client_data == NULL)
        return;

    if ((*client_data)->_pre_destroy_client_data) {
        (*client_data)->_pre_destroy_client_data(*client_data);
    }
    free((*client_data)->name);
    free(*client_data);
    *client_data = NULL;
}
