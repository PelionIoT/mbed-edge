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

#include <string.h>
#include <stdlib.h>

#include "common/constants.h"
#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_device_object.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt-dev-res"

/*
 * Prototype for error code resource creation.
 */
static pt_status_t ptdo_initialize_error_code_resource(connection_id_t connection_id_t,
                                                       const char *device_id,
                                                       pt_resource_callback reset_error_code_callback);

/*
 * Prototype for internal readable string resources creation.
 */
static pt_status_t ptdo_initialize_string_resources(connection_id_t connection_id_t,
                                                    const char *device_id,
                                                    const ptdo_device_object_data_t *device_object_data);

pt_status_t ptdo_initialize_device_object(connection_id_t connection_id,
                                          const char *device_id,
                                          const ptdo_device_object_data_t *device_object_data)
{
    if (!device_id) {
        tr_err("Device ID parameter was NULL.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    if (!device_object_data) {
        tr_err("Device object data parameter was NULL.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    /*
     * Reboot executable resource is mandatory by LWM2M device resource spec.
     */
    if (!device_object_data->reboot_callback) {
        tr_err("Reboot callback was NULL.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    /*
     * Reboot executable resource.
     */
    pt_status_t status = pt_device_add_resource_with_callback(connection_id,
                                                              device_id,
                                                              PT_DEVICE_OBJECT_ID,
                                                              0,
                                                              PT_REBOOT_RESOURCE_ID,
                                                              LWM2M_OPAQUE,
                                                              OPERATION_EXECUTE,
                                                              /* value */ NULL,
                                                              /* value size */ 0,
                                                              free,
                                                              device_object_data->reboot_callback);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    /*
     * Factory reset executable resource.
     */
    if (device_object_data->factory_reset_callback) {
        status = pt_device_add_resource_with_callback(connection_id,
                                                      device_id,
                                                      PT_DEVICE_OBJECT_ID,
                                                      0,
                                                      PT_FACTORY_RESET_RESOURCE_ID,
                                                      LWM2M_OPAQUE,
                                                      OPERATION_EXECUTE,
                                                      /* value */ NULL,
                                                      /* value size */ 0,
                                                      free,
                                                      device_object_data->factory_reset_callback);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    status = ptdo_initialize_error_code_resource(connection_id, device_id, device_object_data->reset_error_code_callback);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resources(connection_id, device_id, device_object_data);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    return PT_STATUS_SUCCESS;
}

static pt_status_t ptdo_initialize_error_code_resource(connection_id_t connection_id,
                                                       const char *device_id,
                                                       pt_resource_callback reset_error_code_callback)
{
    pt_status_t status;
    /*
     * Error code resource, mandatory
     */
    uint8_t *error_code = calloc(1, sizeof(uint16_t));
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    PT_DEVICE_OBJECT_ID,
                                    0,
                                    PT_ERROR_CODE_RESOURCE_ID,
                                    LWM2M_INTEGER,
                                    (uint8_t *) error_code,
                                    sizeof(uint16_t),
                                    free);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    if (reset_error_code_callback) {
        status = pt_device_add_resource_with_callback(connection_id,
                                                      device_id,
                                                      PT_DEVICE_OBJECT_ID,
                                                      0,
                                                      PT_RESET_ERROR_CODE_RESOURCE_ID,
                                                      LWM2M_OPAQUE,
                                                      OPERATION_EXECUTE,
                                                      /* value */ NULL,
                                                      /* value size */ 0,
                                                      NULL,
                                                      reset_error_code_callback);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    return PT_STATUS_SUCCESS;
}

static pt_status_t ptdo_initialize_string_resource(connection_id_t connection_id,
                                                   const char *device_id,
                                                   const uint16_t resource_id,
                                                   const char *resource_value)
{
    pt_status_t status = PT_STATUS_SUCCESS;

    if (resource_value) {
        status = PT_STATUS_ALLOCATION_FAIL;
        char *temp_buf = strdup(resource_value);
        if (temp_buf) {
            status = pt_device_add_resource(connection_id,
                                            device_id,
                                            PT_DEVICE_OBJECT_ID,
                                            0,
                                            resource_id,
                                            LWM2M_STRING,
                                            (uint8_t *) temp_buf,
                                            strlen(temp_buf),
                                            free);
        }
    }

    return status;
}

static pt_status_t ptdo_initialize_string_resources(connection_id_t connection_id,
                                                    const char *device_id,
                                                    const ptdo_device_object_data_t *device_object_data)
{
    pt_status_t status;

    // Copy the string values as they could be passed as statics or stack allocated and
    // we don't get the free function from the parameter.

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_MANUFACTURER_RESOURCE_ID,
                                             device_object_data->manufacturer);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_MODEL_NUMBER_RESOURCE_ID,
                                             device_object_data->model_number);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_SERIAL_NUMBER_RESOURCE_ID,
                                             device_object_data->serial_number);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_FIRMWARE_VERSION_RESOURCE_ID,
                                             device_object_data->firmware_version);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_HARDWARE_VERSION_RESOURCE_ID,
                                             device_object_data->hardware_version);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_SOFTWARE_VERSION_RESOURCE_ID,
                                             device_object_data->software_version);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    status = ptdo_initialize_string_resource(connection_id,
                                             device_id,
                                             PT_DEVICE_TYPE_RESOURCE_ID,
                                             device_object_data->device_type);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    return PT_STATUS_SUCCESS;
}
