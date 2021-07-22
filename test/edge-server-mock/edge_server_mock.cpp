/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdint.h>
#include "edge-client/edge_client.h"
#ifdef MBED_EDGE_SUBDEVICE_FOTA
#include "edge-client/subdevice_fota.h"
#include "test_fota_config.h"
#endif
#include "CppUTestExt/MockSupport.h"
#include <curl/curl.h>

#ifdef MBED_EDGE_SUBDEVICE_FOTA

#define VENDOR_ID "SUBDEVICE-VENDOR"
#define CLASS_ID "SUBDEVICE--CLASS"
#define FIRMWARE_VERSION 1000
#define PAYLOAD_SIZE 100000

#endif // MBED_EDGE_SUBDEVICE_FOTA

extern "C" {
    void edgeserver_exit_event_loop()
    {
        mock().actualCall("edgeserver_exit_event_loop");
    }

    void edgeserver_graceful_shutdown()
    {
        mock().actualCall("edgeserver_graceful_shutdown");
    }

    bool edgeserver_remove_protocol_translator_nodes()
    {
        return mock().actualCall("edgeserver_remove_protocol_translator_nodes")
                .returnBoolValue();
    }
    void edgeserver_resource_async_request(edgeclient_request_context_t *request_ctx)
    {
        mock().actualCall("edgeserver_resource_async_request")
                .withPointerParameter("request_ctx", (void *) request_ctx);
    }

    bool edgeserver_execute_rfs_customer_code(edgeclient_request_context_t *request_ctx) {
        return mock().actualCall("edgeserver_execute_rfs_customer_code").returnBoolValue();
    }

    void edgeserver_rfs_customer_code_succeeded()
    {
        mock().actualCall("edgeserver_rfs_customer_code_succeeded");
    }

    struct event_base *edge_server_get_base()
    {
        return (struct event_base *) mock().actualCall("edge_server_get_base")
                .returnPointerValue();
    }
    #ifdef MBED_EDGE_SUBDEVICE_FOTA

    int fota_manifest_parse( const uint8_t *input_data, size_t input_size, manifest_firmware_info_t *fw_info) {
        char real_url[FILENAME_MAX] = DUMMY_BINARY_LOCATION;
        fw_info->version = FIRMWARE_VERSION;
        fw_info->payload_size = PAYLOAD_SIZE;
        memcpy(fw_info->uri, real_url, strlen(real_url));
        memcpy(fw_info->component_name, "MAIN", strlen("MAIN"));
        memcpy(fw_info->vendor_id,VENDOR_ID, 16);
        memcpy(fw_info->class_id, CLASS_ID, 16);
        return copy_buff(fw_info);
    }
    int fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state) {
        return mock().actualCall("fota_is_ready").withParameter("data", data).withParameter("data_size", size).withOutputParameter("fota_state", fota_state).returnIntValue();
    }
    void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version) {

    }
    void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc) {

    }
    int fota_component_name_to_id(const char *name, unsigned int *comp_id) {

    }
    #endif // MBED_EDGE_SUBDEVICE_FOTA
}
