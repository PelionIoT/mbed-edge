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

#ifndef IPSO_ENUMS_H
#define IPSO_ENUMS_H

enum IPSO_OBJECTS {
    DIGITAL_OUTPUT = 3201,
    TEMPERATURE_SENSOR = 3303,
    HUMIDITY_SENSOR = 3304,
    CONCENTRATION_SENSOR = 3325,
    SET_POINT = 3308,
    FIRMWARE_UPDATE = 5
};

enum IPSO_RESOURCES {
    MIN_MEASURED_VALUE = 5601,
    MAX_MEASURED_VALUE = 5602,
    RESET_MIN_MAX_MEASURED_VALUES = 5605,
    SENSOR_VALUE = 5700,
    SENSOR_UNITS = 5701,
    SENSOR_TYPE = 5751,
    ON_OFF_VALUE = 5850,
    SET_POINT_VALUE = 5900
};

#endif
