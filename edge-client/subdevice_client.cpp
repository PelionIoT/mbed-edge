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
#include "arm_uc_public.h"

int ARM_UC_SUBDEVICE_ReportUpdateResult(const char *endpoint_name, char *error_manifest)
{
    pt_api_result_code_e err = PT_API_UNKNOWN_ERROR;
    if (strcmp(&error_manifest[0], "0")) // reset manifest hash/version in case of error
    {
        err = edgeclient_set_resource_value(endpoint_name,
                                            MANIFEST_OBJECT,
                                            MANIFEST_INSTANCE,
                                            MANIFEST_ASSET_HASH,
                                            "",
                                            (const uint8_t *) "0",
                                            1,
                                            LWM2M_STRING,
                                            1,
                                            NULL);
        err = edgeclient_set_resource_value(endpoint_name,
                                            MANIFEST_OBJECT,
                                            MANIFEST_INSTANCE,
                                            MANIFEST_VERSION,
                                            "",
                                            (const uint8_t *) "0",
                                            1,
                                            LWM2M_STRING,
                                            1,
                                            NULL);

        err = edgeclient_set_resource_value(endpoint_name,
                                            MANIFEST_OBJECT,
                                            MANIFEST_INSTANCE,
                                            MANIFEST_RESOURCE_RESULT,
                                            "",
                                            (const uint8_t *) error_manifest,
                                            strlen(error_manifest),
                                            LWM2M_STRING,
                                            1,
                                            NULL);
    }

    tr_info("ARM_UC_SUBDEVICE_ReportUpdateResult Status update stop == %d", err);
}

void manifest_callback(void *_parameters)
{
    M2MResource::M2MExecuteParameter *exec_params = (M2MResource::M2MExecuteParameter *) _parameters;
    M2MResource *resource = exec_params->get_resource();
    arm_uc_update_result_t *error_manifest = (arm_uc_update_result_t *) malloc(sizeof(arm_uc_update_result_t));
    if (error_manifest == NULL) {
        tr_err("Memory Allocation Error %s %d", __FUNCTION__, __LINE__);
        return;
    }
    memset(error_manifest, 0, sizeof(arm_uc_update_result_t));
    if (resource->uri_path() == NULL) {
        free(error_manifest);
        return;
    }
    char *uri_path = strdup(resource->uri_path()); // URI : d/device_id/10252/0/1
    char *left_string = NULL;
    char *manifest_res = NULL;
    strtok_r(uri_path, "/", &left_string); // left_string : device_id/10252/0/1
    char *device_id = strtok_r(left_string, "/", &manifest_res);
    char err_str[3] = " "; // for storing the error into string
    if (strcmp(manifest_res, xstr(MANIFEST_INFORMATION))) {
        tr_err("Not the subdevice manifest %s", uri_path);
        free(error_manifest);
        return;
    }
    tr_debug("manifest for subdevice %s payload len %d", device_id, exec_params->get_argument_value_length());

    uint8_t *manifest = (uint8_t *) exec_params->get_argument_value();
    arm_uc_buffer_t manifest_buffer;
    manifest_buffer.ptr = manifest;
    manifest_buffer.size = exec_params->get_argument_value_length();
    manifest_buffer.size_max = 1024;
    manifest_info_t manifest_info = {0};
    bool manifest_check = parse_manifest_for_subdevice(&manifest_buffer, &manifest_info, error_manifest);
    itoa_c(*error_manifest, err_str);
    tr_debug("Error Code from Manifest :%d %s", *error_manifest, err_str);
    ARM_UC_SUBDEVICE_ReportUpdateResult(device_id, err_str);
    free(error_manifest);
    if (uri_path)
        free(uri_path);
    resource->set_manifest_check_status(manifest_check);
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
        res->set_execute_function(manifest_callback);
    }

    if ((object_id == DEVICE_META_OBJECT || object_id == MANIFEST_OBJECT) && object_instance_id == MANIFEST_INSTANCE) {
        res->publish_value_in_registration_msg(true);
    }

    return PT_API_SUCCESS;
}

#endif // MBED_EDGE_SUBDEVICE_FOTA