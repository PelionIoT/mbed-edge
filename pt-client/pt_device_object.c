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

#include "common/constants.h"
#include "pt-client/pt_api.h"
#include "pt-client/pt_device_object.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt-dev-res"

/*
 * Prototype for error code resource creation.
 */
static pt_status_t ptdo_initialize_error_code_resource(pt_object_instance_t *instance,
                                                       pt_resource_callback reset_error_code_callback);

/*
 * Prototype for internal readable string resources creation.
 */
static pt_status_t ptdo_initialize_string_resources(pt_object_instance_t *instance,
                                                    ptdo_device_object_data_t *device_object_data);

pt_status_t ptdo_initialize_device_object(pt_device_t *device,
                                          ptdo_device_object_data_t *device_object_data)
{
    if (!device) {
        tr_err("Device parameter was NULL.");
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

    pt_status_t status;
    pt_object_t *object = pt_device_add_object(device, PT_DEVICE_OBJECT_ID, &status);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    pt_object_instance_t *instance = pt_object_add_object_instance(object, 0, &status);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    /*
     * Reboot executable resource.
     */
    (void*) pt_object_instance_add_resource_with_callback(instance, PT_REBOOT_RESOURCE_ID,
                                                          LWM2M_OPAQUE, OPERATION_EXECUTE,
                                                          /* value */ NULL, /* value size */ 0,
                                                          &status, device_object_data->reboot_callback);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }


    /*
     * Factory reset executable resource.
     */
    if (device_object_data->factory_reset_callback) {
        (void*) pt_object_instance_add_resource_with_callback(instance, PT_FACTORY_RESET_RESOURCE_ID,
                                                              LWM2M_OPAQUE, OPERATION_EXECUTE,
                                                              /* value */ NULL, /* value size */ 0,
                                                              &status, device_object_data->factory_reset_callback);

        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }


    status = ptdo_initialize_error_code_resource(instance, device_object_data->reset_error_code_callback);

    status = ptdo_initialize_string_resources(instance, device_object_data);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    return PT_STATUS_SUCCESS;
}

static pt_status_t ptdo_initialize_error_code_resource(pt_object_instance_t *instance,
                                                       pt_resource_callback reset_error_code_callback)
{
    pt_status_t status;
    /*
     * Error code resource, mandatory
     */
    uint16_t *error_code = calloc(1, sizeof(uint16_t));
    (void*) pt_object_instance_add_resource(instance, PT_ERROR_CODE_RESOURCE_ID,
                                            LWM2M_INTEGER,
                                            (uint8_t*) error_code, sizeof(uint16_t),
                                            &status);

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    if (reset_error_code_callback) {
        (void*) pt_object_instance_add_resource_with_callback(instance, PT_RESET_ERROR_CODE_RESOURCE_ID,
                                                              LWM2M_OPAQUE, OPERATION_EXECUTE,
                                                              /* value */ NULL, /* value size */ 0,
                                                              &status, reset_error_code_callback);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    return PT_STATUS_SUCCESS;
}

static pt_status_t ptdo_initialize_string_resources(pt_object_instance_t *instance,
                                                    ptdo_device_object_data_t *device_object_data)
{
    pt_status_t status;

    if (!device_object_data) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    if (device_object_data->manufacturer) {
        (void*) pt_object_instance_add_resource(instance, PT_MANUFACTURER_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->manufacturer,
                                                strlen(device_object_data->manufacturer),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->model_number) {
        (void*) pt_object_instance_add_resource(instance, PT_MODEL_NUMBER_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->model_number,
                                                strlen(device_object_data->model_number),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->serial_number) {
        (void*) pt_object_instance_add_resource(instance, PT_SERIAL_NUMBER_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->serial_number,
                                                strlen(device_object_data->serial_number),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->firmware_version) {
        (void*) pt_object_instance_add_resource(instance, PT_FIRMWARE_VERSION_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->firmware_version,
                                                strlen(device_object_data->firmware_version),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->hardware_version) {
        (void*) pt_object_instance_add_resource(instance, PT_HARDWARE_VERSION_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->hardware_version,
                                                strlen(device_object_data->hardware_version),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->software_version) {
        (void*) pt_object_instance_add_resource(instance, PT_SOFTWARE_VERSION_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->software_version,
                                                strlen(device_object_data->software_version),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    if (device_object_data->device_type) {
        (void*) pt_object_instance_add_resource(instance, PT_DEVICE_TYPE_RESOURCE_ID,
                                                LWM2M_STRING,
                                                (uint8_t*) device_object_data->device_type,
                                                strlen(device_object_data->device_type),
                                                &status);
        if (PT_STATUS_SUCCESS != status) {
            return status;
        }
    }

    return PT_STATUS_SUCCESS;
}
