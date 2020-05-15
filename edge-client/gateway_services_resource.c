/*
 * ----------------------------------------------------------------------------
 * Copyright 2020 ARM Ltd.
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

#define TRACE_GROUP "edgegsr"
#include "edge-client/edge_client.h"
#include <stddef.h>
#include <string.h>
#include "mbed-trace/mbed_trace.h"
#include "edge-client/edge_core_cb_result.h"
#include "edge-client/gateway_services_resource.h"

static int gsr_add_service_instance(uint16_t obj_instance_id, uint8_t* id, uint32_t id_len, uint8_t* enabled, uint8_t* config, uint32_t config_len)
{
    pt_api_result_code_e result = edgeclient_set_resource_value(NULL,
                                                                EDGE_SERVICEMGMT_OBJECT_ID,
                                                                obj_instance_id,
                                                                EDGE_SERVICE_ID,
                                                                id,
                                                                id_len,
                                                                LWM2M_STRING,
                                                                OPERATION_READ,
                                                                /* userdata */ NULL);
    if(result != PT_API_SUCCESS) {
      tr_debug("Failed to add service_id resource, error - %d", result);
      return -1;
    }

    result = edgeclient_set_resource_value(NULL,
                                  EDGE_SERVICEMGMT_OBJECT_ID,
                                  obj_instance_id,
                                  EDGE_SERVICE_ENABLED,
                                  enabled,
                                  1,
                                  LWM2M_BOOLEAN,
                                  OPERATION_READ_WRITE,
                                  /* userdata */ NULL);
    if(result != PT_API_SUCCESS) {
      tr_debug("Failed to add service_id resource, error - %d", result);
      return -1;
    }

    result = edgeclient_set_resource_value(NULL,
                                  EDGE_SERVICEMGMT_OBJECT_ID,
                                  obj_instance_id,
                                  EDGE_SERVICE_CONFIG,
                                  config,
                                  config_len,
                                  LWM2M_STRING,
                                  OPERATION_READ_WRITE,
                                  /* userdata */ NULL);
    if(result != PT_API_SUCCESS) {
      tr_debug("Failed to add service_id resource, error - %d", result);
      return -1;
    }

    return 1;
}

static pt_api_result_code_e gsr_update_service_config(uint16_t obj_instance_id, uint8_t* value, uint8_t len)
{
    return edgeclient_update_resource_value(NULL,
                                  EDGE_SERVICEMGMT_OBJECT_ID,
                                  obj_instance_id,
                                  EDGE_SERVICE_CONFIG,
                                  value,
                                  len);
}

static pt_api_result_code_e gsr_update_service_enabled(uint16_t obj_instance_id, uint8_t* value)
{
    return edgeclient_update_resource_value(NULL,
                                  EDGE_SERVICEMGMT_OBJECT_ID,
                                  obj_instance_id,
                                  EDGE_SERVICE_ENABLED,
                                  value,
                                  1);
}

void gsr_resource_requested(edgeclient_request_context_t *request_ctx)
{
    tr_info("Gateway services resource request received");
    pt_api_result_code_e result = -30102;
    switch(request_ctx->resource_id) {
      case 1:
          result = gsr_update_service_enabled((uint16_t)request_ctx->object_instance_id, request_ctx->value);
          break;
      case 2:
          result = gsr_update_service_config((uint16_t)request_ctx->object_instance_id, request_ctx->value, request_ctx->value_len);
          break;
    }

    if(result == PT_API_SUCCESS) {
        tr_debug("gsr resource requested successful");
        edgecore_async_cb_success(request_ctx);
    } else {
        tr_debug("gsr resource requested failed, code %d", result);
       edgecore_async_cb_failure(request_ctx);
    }
}

void gsr_add_gateway_services_resource()
{
    uint16_t obj_instance_id;
    const char*  feature_ids[] = {"urn:fid:pelion.com:terminal:0.0.1",
                        "urn:fid:pelion.com:log:0.0.1",
                        "urn:fid:pelion.com:kaas:0.0.1",
                        "urn:fid:pelion.com:stats:0.0.1",
                        "urn:fid:pelion.com:devicejs:0.0.1",
                        "urn:fid:pelion.com:devicedb:0.0.1",
                        "urn:fid:pelion.com:alerts:0.0.1"};
    uint32_t feature_id_len;
    uint8_t service_enabled = 1;
    uint32_t config_len = 2;
    char config[] = "{}";

    for(obj_instance_id = 0; obj_instance_id < 7; obj_instance_id++) {
        feature_id_len = strlen(feature_ids[obj_instance_id]);
        if(gsr_add_service_instance(obj_instance_id, (uint8_t *)feature_ids[obj_instance_id], feature_id_len, &service_enabled, (uint8_t *)&config, config_len) == 1)
            tr_info("Service instance %d with feature id %s added successfully", obj_instance_id, feature_ids[obj_instance_id]);
    }
}


