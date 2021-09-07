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

#ifdef MBED_EDGE_SUBDEVICE_FOTA
#define TRACE_GROUP "edgesd"

extern "C" {
#include "edge-core/edge_server.h"
}

#include "edge-client/edge_client.h"
#include "edge-client/edge_manifest_object.h"
extern "C" {
#include "edge-client/edge_client_format_values.h"
}

#include "edge-client/edge_client_internal.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mresource.h"
#include "edge-client/subdevice_fota.h"

void manifest_callback_subdevice(void *_parameters) {
    tr_info("manifest_callback_subdevice");
    M2MResource::M2MExecuteParameter *exec_params = (M2MResource::M2MExecuteParameter *) _parameters;
    uint8_t *buffer = (uint8_t *) exec_params->get_argument_value();
    uint16_t length = exec_params->get_argument_value_length();
    M2MResource *resource = exec_params->get_resource();
    fota_state_e fota_state;
    char device_id[ENDPOINT_SIZE] = {0};
    get_endpoint(device_id, resource->uri_path());
    int ret = fota_is_ready(buffer, length, &fota_state);
    if (ret == FOTA_STATUS_OUT_OF_MEMORY) {
        memset(buffer, 0, length);
        uint8_t res = -1*FOTA_STATUS_OUT_OF_MEMORY;
        update_state_resource(device_id, FOTA_STATE_INVALID);
        update_result_resource(device_id, res);
        resource->send_delayed_post_response();
        resource->set_manifest_check_status(false);
        return;
        }
    uint8_t reset_val = -1;
    uint8_t res= 0;
     switch (fota_state) {
        case FOTA_STATE_IDLE: {
            update_state_resource(device_id, reset_val);
            update_result_resource(device_id, reset_val);
            resource->send_delayed_post_response();
            subdevice_fota_on_manifest(buffer, length, resource);
            break;
        }
        case FOTA_STATE_INVALID:
            FOTA_TRACE_ERROR("FOTA cannot handle manifest - rejecting");
            update_state_resource(device_id, FOTA_STATE_INVALID);
            res = -1*FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED;
            update_result_resource(device_id, res);
            resource->send_delayed_post_response();
            resource->set_manifest_check_status(false);
            break;
        default:
            resource->set_manifest_check_status(false);
            break;
    }
}

pt_api_result_code_e subdevice_set_resource_value(const char *endpoint_name,
                                                  const uint16_t object_id,
                                                  const uint16_t object_instance_id,
                                                  const uint16_t resource_id,
                                                  const char* resource_name,
                                                  const uint8_t *value,
                                                  const uint32_t value_length,
                                                  Lwm2mResourceType resource_type,
                                                  int opr,
                                                  void *ctx)
{
    if (!edgeclient_create_resource_structure(endpoint_name,
                                              object_id,
                                              object_instance_id,
                                              resource_id,
                                              resource_name,
                                              resource_type,
                                              opr,
                                              ctx)) {
        tr_error("set_endpoint_resource_value - could not create resource structure!");
        return PT_API_INTERNAL_ERROR;
    }

    M2MResource *res = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (res == NULL) {
        return PT_API_INTERNAL_ERROR;
    }

    if (value != NULL && value_length > 0) {
        char *text_format = NULL;
        size_t text_format_length = value_to_text_format(resource_type, value, value_length, &text_format);
        if (text_format_length > 0 && text_format != NULL) {
            res->update_value((uint8_t *) text_format, text_format_length);
        } else {
            return PT_API_ILLEGAL_VALUE;
        }
    }

    res->set_manifest_check_status(true);
    if ((object_id == MANIFEST_OBJECT) && (object_instance_id == MANIFEST_INSTANCE) &&
        ((resource_id == MANIFEST_RESOURCE_STATE) || (resource_id == MANIFEST_RESOURCE_RESULT))) {
        res->set_auto_observable(true);
    }

    if ((object_id == MANIFEST_OBJECT) && (object_instance_id == MANIFEST_INSTANCE) &&
        resource_id == MANIFEST_RESOURCE_PAYLOAD) {
        res->set_execute_function(manifest_callback_subdevice);
    }

    if ((object_id == DEVICE_META_OBJECT || object_id == MANIFEST_OBJECT) && object_instance_id == MANIFEST_INSTANCE) {
        res->publish_value_in_registration_msg(true);
    }

    return PT_API_SUCCESS;
}

#endif // MBED_EDGE_SUBDEVICE_FOTA