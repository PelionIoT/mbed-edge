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

#include <float.h>
#include <jansson.h>
#include "ipso_objects.h"
#include "common/constants.h"
#include "common/integer_length.h"
#include "pt-client/pt_api.h"
#include "pt-example/byte_order.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "ipso-objects"

void add_optional_thermometer_fields(pt_object_instance_t *instance,
                                     pt_resource_callback reset_thermometer_callback)
{
    pt_status_t status = PT_STATUS_SUCCESS;

    float min_default = FLT_MAX; // Set minimum measured on default to max float
    uint8_t *min_default_temperature_data = malloc(sizeof(float));
    convert_float_value_to_network_byte_order(min_default, min_default_temperature_data);

    float max_default = FLT_MIN; // Set maximum measured on default to min float
    uint8_t *max_default_temperature_data = malloc(sizeof(float));
    convert_float_value_to_network_byte_order(max_default, max_default_temperature_data);

    (void)pt_object_instance_add_resource(instance, MIN_MEASURED_VALUE,
                                          LWM2M_FLOAT,
                                          min_default_temperature_data,
                                          sizeof(float),
                                          &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create resource with id (%d) to the object_instance (%d).",
               MIN_MEASURED_VALUE, instance->id);
    }

    (void)pt_object_instance_add_resource(instance, MAX_MEASURED_VALUE,
                                          LWM2M_FLOAT,
                                          max_default_temperature_data,
                                          sizeof(float),
                                          &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create resource with id (%d) to the object_instance (%d).",
               MAX_MEASURED_VALUE, instance->id);
    }

    (void)pt_object_instance_add_resource_with_callback(instance, RESET_MIN_MAX_MEASURED_VALUES,
                                                        LWM2M_OPAQUE,
                                                        OPERATION_EXECUTE,
                                                        NULL,
                                                        0,
                                                        &status, reset_thermometer_callback);

    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create resource with id (%d) to the object_instance (%d).",
               RESET_MIN_MAX_MEASURED_VALUES, instance->id);
    }
}

void ipso_create_thermometer(pt_device_t *device, const uint16_t object_instance_id, const float temperature, bool optional_fields, pt_resource_callback reset_thermometer_callback)
{
    pt_status_t status = PT_STATUS_SUCCESS;

    pt_object_t *object = pt_device_add_object(device, TEMPERATURE_SENSOR, &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create an object with id (%d) to the device (%s).",
               TEMPERATURE_SENSOR, device->device_id);
    }

    pt_object_instance_t *instance =
        pt_object_add_object_instance(object, object_instance_id, &status);

    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create an object instance with id (%d) to the object (%d).",
               object_instance_id, TEMPERATURE_SENSOR);
    }

    uint8_t *temperature_data = malloc(sizeof(float));
    convert_float_value_to_network_byte_order(temperature, (uint8_t *) temperature_data);

    // Add sensor value resource
    (void)pt_object_instance_add_resource(instance, SENSOR_VALUE,
                                          LWM2M_FLOAT,
                                          temperature_data,
                                          sizeof(float),
                                          &status);

    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create a resource with id (%d) to the object_instance (%d).",
               SENSOR_VALUE, object_instance_id);
    }

    // Add units resource
    (void)pt_object_instance_add_resource(instance, SENSOR_UNITS,
                                          LWM2M_STRING,
                                          (uint8_t*) strdup("Cel"),
                                          strlen("Cel"),
                                          &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create a resource with id (%d) to the object_instance (%d).",
               SENSOR_UNITS, object_instance_id);
    }

    if (optional_fields) {
        if (reset_thermometer_callback) {
            add_optional_thermometer_fields(instance, reset_thermometer_callback);
        } else {
            add_optional_thermometer_fields(instance, ipso_reset_thermometer_min_max);
        }
    }
}

void ipso_reset_thermometer_min_max(const pt_resource_opaque_t *resource, const uint8_t* value, uint32_t value_len, void *userdata)
{
    tr_info("Resetting min and max to default values on '%s'.",
        resource->parent->parent->parent->device_id);
    pt_resource_opaque_t *min =
        pt_object_instance_find_resource(resource->parent, MIN_MEASURED_VALUE);
    if (min) {
        float min_default = FLT_MAX; // Set minimum measured on reset to max float
        uint8_t *min_default_temperature_data = malloc(sizeof(float));
        convert_float_value_to_network_byte_order(min_default, min_default_temperature_data);
        memcpy(min->value, min_default_temperature_data, sizeof(float));
        free(min_default_temperature_data);
    }

    pt_resource_opaque_t *max =
        pt_object_instance_find_resource(resource->parent, MAX_MEASURED_VALUE);
    if (max) {
        float max_default = FLT_MIN; // Set maximum measured on reset to min float
        uint8_t *max_default_temperature_data = malloc(sizeof(float));
        convert_float_value_to_network_byte_order(max_default, max_default_temperature_data);
        memcpy(max->value, max_default_temperature_data, sizeof(float));
        free(max_default_temperature_data);
    }
}

void ipso_write_set_point_value(const pt_resource_opaque_t *resource, const uint8_t* value, const uint32_t value_size, void *ctx)
{
    tr_warn("Set point default value write not implemented.");
}

void ipso_create_set_point(pt_device_t *device, uint16_t object_instance_id, float target_temperature)
{
    pt_status_t status = PT_STATUS_SUCCESS;

    pt_object_t *object = pt_device_add_object(device, SET_POINT, &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create an object with id (%d) to the device (%s).",
               SET_POINT, device->device_id);
    }

    pt_object_instance_t *instance =
        pt_object_add_object_instance(object, object_instance_id, &status);

    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create an object instance with id (%d) to the object (%d).", object_instance_id, SET_POINT);
    }

    uint8_t *temperature_data = malloc(sizeof(float));
    memcpy(temperature_data, &target_temperature, sizeof(float));

    // Add set point read write resource
    (void)pt_object_instance_add_resource_with_callback(instance, SET_POINT_VALUE,
                                                        LWM2M_FLOAT,
                                                        OPERATION_READ_WRITE,
                                                        temperature_data,
                                                        sizeof(float),
                                                        &status, ipso_write_set_point_value);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create a resource with id (%d) to the object_instance (%d/%d).",
               SET_POINT_VALUE, SET_POINT, object_instance_id);
    }

    // Add units resource
    (void)pt_object_instance_add_resource(instance, SENSOR_UNITS,
                                          LWM2M_STRING,
                                          (uint8_t*) strdup("Cel"),
                                          strlen("Cel"),
                                          &status);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create a resource with id (%d) to the object_instance (%d/%d).",
               SENSOR_UNITS, SET_POINT, object_instance_id);
    }
}

#define HEX_CHARS "0123456789ABCDEF"
char* ipso_convert_value_to_hex_string(uint8_t *data, const uint32_t value_size)
{
    // Representation is in format AA:BB:CC...
    char *str = calloc(value_size * 3 + /* NUL */ 1, sizeof(char));
    uint8_t * data_offset = data;
    int str_index = 0;
    for (int i = 0; i < value_size; i++, data_offset++, str_index+=3) {
        str[str_index] = HEX_CHARS[(*data_offset >> 4) & 0xF];
        str[str_index+1] = HEX_CHARS[*data_offset & 0xF];
        str[str_index+2] = ':';
    }

    return str;
}

int ipso_object_to_json_string(pt_object_t *object, char** data)
{
    json_t *js_root = json_object();
    json_t *js_instances = json_array();
    json_object_set_new(js_root, "object-id", json_integer(object->id));
    json_object_set_new(js_root, "instances", js_instances);

    ns_list_foreach(pt_object_instance_t, instance, object->instances) {
        json_t *js_instance = json_object();
        json_array_append_new(js_instances, js_instance);

        json_t *js_resources = json_array();
        json_object_set_new(js_instance, "resources", js_resources);
        json_object_set_new(js_instance, "instance-id", json_integer(instance->id));

        ns_list_foreach(pt_resource_t, resource_abs, instance->resources) {
            pt_resource_opaque_t *resource = (pt_resource_opaque_t*) resource_abs;
            json_t *js_resource = json_object();
            json_array_append_new(js_resources, js_resource);
            json_object_set_new(js_resource, "resource-id", json_integer(resource->id));
            json_object_set_new(js_resource, "operations", json_integer(resource->operations));
            json_object_set_new(js_resource, "value_size", json_integer(resource->value_size));
            char* value_in_hex = ipso_convert_value_to_hex_string(resource->value,
                                                                  resource->value_size);
            json_object_set_new(js_resource, "value", json_string(value_in_hex));
            free(value_in_hex);
        }
    }
    *data = json_dumps(js_root, JSON_INDENT(1) | JSON_SORT_KEYS);
    json_decref(js_root);
    return 0;
}
