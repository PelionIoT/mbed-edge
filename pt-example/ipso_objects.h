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

#ifndef EDGE_IPSO_OBJECTS_H
#define EDGE_IPSO_OBJECTS_H

#include "pt-client/pt_api.h"

enum IPSO_OBJECTS {
    TEMPERATURE_SENSOR = 3303,
    SET_POINT          = 3308
};

enum IPSO_RESOURCES {
    MIN_MEASURED_VALUE            = 5601,
    MAX_MEASURED_VALUE            = 5602,
    RESET_MIN_MAX_MEASURED_VALUES = 5605,
    SENSOR_VALUE                  = 5700,
    SENSOR_UNITS                  = 5701,
    SET_POINT_VALUE               = 5900
};

void ipso_create_thermometer(pt_device_t *device, uint16_t object_instance_id,float temperature,
                             bool optional_fields, pt_resource_callback reset_thermometer_callback);
void ipso_create_set_point(pt_device_t *device, uint16_t object_instance_id, float target_temperature);

/**
 * \brief Default example thermometer mix and max reset callback
 * See ::pt_device_resource_execute
 */
void ipso_reset_thermometer_min_max(const pt_resource_opaque_t *resource, const uint8_t* value, const uint32_t value_length, void *userdata);

int ipso_object_to_json_string(pt_object_t *object, char** data);
#endif /* EDGE_IPSO_OBJECTS_H */
