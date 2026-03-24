/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
 */

#ifdef MBED_EDGE_ENABLE_BYOC_JSON

#define TRACE_GROUP "edgekcm"

#include "edge-client/edge_client_byoc_with_json.h"
#include "common/read_file.h"
#include "mbed-trace/mbed_trace.h"

#include "fcc_status.h"
#include "fcc_bundle_handler.h"
#include "factory_configurator_client.h"
#include "common/json2cbor.h"

byoc_data_t *edgeclient_create_byoc_data(char *cbor_file, char *json_file)
{
    byoc_data_t *byoc_data = calloc(1, sizeof(byoc_data_t));
    if (!byoc_data)
    {
        tr_err("Could not allocate memory for byoc_data_t.");
        return NULL;
    }
    byoc_data->cbor_file = cbor_file;
    byoc_data->json_file = json_file;
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

    if (!byoc_data->cbor_file && !byoc_data->json_file)
    {
        tr_info("No BYOC conf given, skipping KCM set.");
        return 0;
    }

    size_t cbor_size;
    uint8_t *cbor_data = NULL;

    if (byoc_data->cbor_file)
    {
        int ret = edge_read_file(byoc_data->cbor_file, &cbor_data, &cbor_size);
        if (0 != ret)
        {
            tr_err("Could not read cbor file: %s", byoc_data->cbor_file);
            return 1;
        }
    }

    if (byoc_data->json_file)
    {
        int ret = json_to_cbor(byoc_data->json_file, &cbor_data, &cbor_size);
        if (0 != ret)
        {
            tr_err("Could not convert json to cbor: %s", byoc_data->json_file);
            return 1;
        }
    }

    fcc_status_e status = FCC_STATUS_SUCCESS;
    tr_info("Deleting configuration storage.");
    fcc_status_e delete_status = fcc_storage_delete();
    if (delete_status != FCC_STATUS_SUCCESS)
    {
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
    if (status == FCC_STATUS_SUCCESS)
    {
        tr_info("BYOC loaded successfully");
    }
    else
    {
        tr_err("ERROR: BYOC failed!");
        exit(-1);
    }
    return 0;
}

#endif // MBED_EDGE_ENABLE_BYOC_JSON