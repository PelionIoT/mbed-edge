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

#define TRACE_GROUP "edgekcm"

#include "edge-client/edge_client_byoc.h"
#include "common/read_file.h"
#include "mbed-trace/mbed_trace.h"

#include "fcc_status.h"
#include "fcc_bundle_handler.h"
#include "factory_configurator_client.h"

byoc_data_t *edgeclient_create_byoc_data(char *cbor_file)
{
    byoc_data_t *byoc_data = calloc(1, sizeof(byoc_data_t));
    if (!byoc_data) {
        tr_err("Could not allocate memory for byoc_data_t.");
        return NULL;
    }
    byoc_data->cbor_file = cbor_file;
    return byoc_data;
}

void edgeclient_destroy_byoc_data(byoc_data_t *byoc_data)
{
    free(byoc_data);
    byoc_data = NULL;
}

int edgeclient_inject_byoc(byoc_data_t *byoc_data)
{
    tr_info("Loading BYOC data to KCM");

    if (!byoc_data->cbor_file) {
        tr_info("No CBOR conf given, skipping KCM set.");
        return 0;
    }

    size_t cbor_size;
    uint8_t *cbor_data = NULL;
    int ret = edge_read_file(byoc_data->cbor_file, &cbor_data, &cbor_size);
    if (0 != ret) {
        tr_err("Could not read cbor file: %s", byoc_data->cbor_file);
        return 1;
    }

    fcc_status_e status = FCC_STATUS_SUCCESS;
    tr_info("Deleting configuration storage.");
    fcc_status_e delete_status = fcc_storage_delete();
    if (delete_status != FCC_STATUS_SUCCESS) {
        tr_error("Failed to delete storage - %d", delete_status);
        exit(1);
    }

    uint8_t *response_protocol_message;
    size_t response_protocol_message_size;
    response_protocol_message = NULL;
    response_protocol_message_size = 0;
    status = fcc_bundle_handler(cbor_data, cbor_size, &response_protocol_message, &response_protocol_message_size);

    free(response_protocol_message);
    free(cbor_data);
    if (status == FCC_STATUS_SUCCESS) {
        tr_info("BYOC loaded successfully");
    }
    else {
        tr_err("ERROR: BYOC failed!");
        exit(-1);
    }
    return 0;
}
