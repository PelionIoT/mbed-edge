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

#ifndef PT_DEVICE_API_INTERNAL_H
#define PT_DEVICE_API_INTERNAL_H

#include "pt-client-2/pt_common_api_internal.h"
#include "pt-client-2/pt_userdata_api.h"

/**
 * \brief Deallocates the reserved memory for the device structure.
 *
 * The structure is iterated and all lists and reserved data structures are freed.
 *
 * \param device_id The structure to deallocate for.
 */
void pt_device_free(pt_device_t *device);

/*
 * \brief Device object add function.
 * \param device Pointer to the device. It may not be NULL.
 * \param id ID of the new Object.
 * \param status returns status of the operation. If it needs to create a new object it returns PT_STATUS_SUCCESS.
 *               If the object already exists, it returns PT_STATUS_ITEM_EXISTS. Other error codes for
 *               failure.
 * \return A pointer to an object structure. If it can't allocate mamory, it returns NULL.
 */
pt_object_t *pt_device_add_object_or_create(pt_device_t *device, const uint16_t id, pt_status_t *status);

/*
 * Device list traversal functions
 */

/**
 * \brief May be used to get the device list from the client
 * \param client The client instance allocated using `pt_client_create`.
 * \return the device list.
 */
pt_devices_t *pt_client_get_devices(pt_client_t *client);

/**
 * \brief Used to retrieve the next device from the device list given the current device.
 * \param devices Pointer to a valid device list. It may not be NULL.
 * \param device The current valid device. It may not be NULL.
 * \return Pointer to the next device if it exists.
 *         NULL If the the device was the last device.
 */
pt_device_t *pt_device_get_next(const pt_device_t *device);

/*
 * Find functions for device and object hierarchy.
 */

/**
 * \brief Used to retrieve the first object of the device.
 * \param device Pointer to a valid device. It may not be NULL.
 * \return The first object in the device's object list.
 */
pt_object_t *pt_device_first_object(const pt_device_t *device);

/**
 * \brief Finds an object from the device.
 *
 * \param device The device object.
 * \param object id The object ID to find from the device.
 * \return The found object pointer or NULL.\n
 *         The ownership of the object is within the `pt_device_t`
 */
pt_object_t *pt_device_find_object(const pt_device_t *device, const uint16_t object_id);

/**
 * \brief Finds an object instance from the device.
 *
 * \param device The device object instance.
 * \param object_id The object ID to find from the device.
 * \param object_instance_id The object instance ID to find from the object.
 *
 * \return The found object instance pointer or NULL.\n
 *         The ownership of the object instance is within the `pt_device_t`
 */
pt_object_instance_t *pt_device_find_object_instance(const pt_device_t *device,
                                                     const uint16_t object_id,
                                                     const uint16_t object_instance_id);

/**
 * \brief Finds a resource from the device.
 *
 * \param device The device object instance.
 * \param object_id The object ID to find from the device.
 * \param object_instance_id The object instance ID to find from the object.
 * \param resource_id The resource ID to find from the device.
 *
 * \return The found resource pointer or NULL.\n
 *         The ownership of the resource is within the `pt_device_t`
 */
pt_resource_t *pt_device_find_resource(const pt_device_t *device,
                                       const uint16_t object_id,
                                       const uint16_t object_instance_id,
                                       const uint16_t resource_id);

/*
 * Device structure functions
 */

/**
 * \brief Adds an object to a device.
 *
 * \param device The device to which the object list is added.
 * \param object_id The object ID of the added object.
 * \param status A pointer to user provided variable for the operation status output.\n
 *        If a device was created, the status is set to `PT_STATUS_SUCCESS`.
 * \return The added empty object.\n
 *         The ownership of the returned object is within the `pt_device_t`.
 */
pt_object_t *pt_device_add_object_or_create(pt_device_t *device, uint16_t object_id, pt_status_t *status);

#endif // PT_DEVICE_API_INTERNAL_H
