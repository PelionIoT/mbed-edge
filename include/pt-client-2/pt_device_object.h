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

#ifndef PT_API_VERSION
#define PT_API_VERSION 2
#endif
#if PT_API_VERSION != 2
#error "Including mixed versions of Protocol API"
#endif

#ifndef PT_DEVICE_OBJECT_H_
#define PT_DEVICE_OBJECT_H_

#include <stdbool.h>
#include "pt-client-2/pt_api.h"

#define PT_DEVICE_OBJECT_ID             3
#define PT_MANUFACTURER_RESOURCE_ID     0
#define PT_MODEL_NUMBER_RESOURCE_ID     1
#define PT_SERIAL_NUMBER_RESOURCE_ID    2
#define PT_FIRMWARE_VERSION_RESOURCE_ID 3
#define PT_REBOOT_RESOURCE_ID           4
#define PT_FACTORY_RESET_RESOURCE_ID    5

#define PT_ERROR_CODE_RESOURCE_ID       11
#define PT_RESET_ERROR_CODE_RESOURCE_ID 12

#define PT_DEVICE_TYPE_RESOURCE_ID      17
#define PT_HARDWARE_VERSION_RESOURCE_ID 18
#define PT_SOFTWARE_VERSION_RESOURCE_ID 19

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

/**
 * \file pt-client-2/pt_device_object.h
 * \brief A utility header to contain the LwM2M device object ID:3 creation for mediated endpoints.
 *
 * See the LwM2M definition for device resource:
 * http://www.openmobilealliance.org/tech/profiles/LWM2M_Device-v1_0_1.xml
 */

/**
 * \brief The device object data ID:3.
 *
 * `NULL` can be passed to optional values and no resource is generated for that field.
 * The parameter strings must be NULL terminated.
 */
typedef struct ptdo_device_object_data {
    const char *manufacturer; /**< The manufacturer information of the device. This is an optional value. */
    const char *model_number; /**< The device model number. This is an optional value. */
    const char *serial_number; /**< The device serial number. This is an optional value. */
    const char *firmware_version; /**< The device's current firmware version. This is an optional value. */
    const char *hardware_version; /**< The device hardware version. This is an optional value. */
    const char *software_version; /**< The device's current software version. This is an optional value. */
    const char *device_type; /**< The device type. This is an optional value. */
    pt_resource_callback reboot_callback; /**< If callback function is given an executable resource ID:5 is created. This is an optional parameter. */
    pt_resource_callback factory_reset_callback; /**< If callback function is given an executable resource ID:5 is created. This is an optional parameter. */
    pt_resource_callback reset_error_code_callback; /**< If callback function is given and executable resource ID:12 is created. This is an optional parameter. */
} ptdo_device_object_data_t;

/**
 * \brief Create the device object ID:3.
 *
 * The following mandatory resources are always generated:
 * - Reboot, executable resource ID:4.
 * - Error code, readable resource ID:11. Supports only one instance.
 *
 * The LwM2M mandatory resource for binding mode ID:16 is not created.
 * Future implementations may create the resource.
 *
 * \param[in] connection_id The connection ID to associate the device objects.
 * \param[in] device_id The device ID to initialize with `\3` object and resources.
 * \param[in] device_object_data The struct containing the values and function pointer for the `\3` object and
 *                               resources. This function assumes that device_object_data structure is initialized.
                                 The function copies the string resource values from the `device_object_data` structure into internal buffers which allows passing in static, stack allocated or heap allocated values.
 * \return The status of the device object initialization operation.\n
 *         `PT_STATUS_SUCCESS` on successful initialize.\n
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t ptdo_initialize_device_object(connection_id_t connection_id,
                                          const char *device_id,
                                          const ptdo_device_object_data_t *device_object_data);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif /* PT_DEVICE_OBJECT_H_ */
