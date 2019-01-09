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

#ifndef PT_DEVICES_API_INTERNAL_H
#define PT_DEVICES_API_INTERNAL_H

#include "pt-client-2/pt_common_api_internal.h"

/**
 * \brief Add a device to device list. After adding the device, remember to register it using `pt_device_register` or
 * `pt_devices_register_devices`.
 */
pt_status_t pt_devices_add_device(pt_devices_t *devices, pt_device_t *device);

/**
 * \brief Remove a device from device list and call pt_device_free for it.
 *        Before this action the devices should/must be unregistered.
 */
pt_status_t pt_devices_remove_and_free_device(pt_devices_t *devices, pt_device_t *device);

/**
 * \brief Remove all the devices from device list and call pt_device_free for them.
 *        The client should unregister the devices.
 * \param devices the device list.
 * \return PT_STATUS_SUCCESS for success. Other error codes for failure.
 */
pt_status_t pt_devices_remove_and_free_all(pt_devices_t *devices);

/**
 * \brief Remove a device from device list. Note: doesn't call pt_device_free. Therefore the memory for
 *        the device is left allocated.
 *        Before removing the device from the list, the client should unregister the device.
 * \param devices the device list.
 * \param device the device that should be removed.
 * \return PT_STATUS_SUCCESS if the device was successfully removed.
 */
pt_status_t pt_devices_remove_device(pt_devices_t *devices, pt_device_t *device);

/**
 * \brief Sets all devices to unregistered state. This needs to be done to reflect the status in Edge
 *        when the connection gets disconneced, because Edge unregisters the devices if connection is lost.
 *        This allows the client to easily reregister the devices by calling
 *        `pt_devices_register_devices`, for example.
 * \param devices the device list.
 */
void pt_devices_set_all_to_unregistered_state(pt_devices_t *devices);

/**
 * \brief Used to retrieve a device from the device list given the device id.
 * \param devices Pointer to a valid device list. It may not be NULL.
 * \param device_id The device to look for.
 * \return Pointer to the device if it was found.
 *         NULL If the device wasn't found.
 */
pt_device_t *pt_devices_find_device(const pt_devices_t *devices, const char *device_id);

/**
 * \brief Finds an object from the device list given the device id and object id.
 * \param devices Pointer to a valid device list. It may not be NULL.
 * \param device_id The device id.
 * \param object_id The id of the object to find.
 * \return Pointer to the object if it was found.
 *         NULL If the object coulnd't be found.
 */
pt_object_t *pt_devices_find_object(const pt_devices_t *devices, const char *device_id, const uint16_t object_id);

/**
 * \brief Finds an object instance from the device list given the device id, object id and object instance id.
 * \param devices Pointer to a valid device list. It may not be NULL.
 * \param device_id The device id.
 * \param object_id The id of the object to find.
 * \param object_instance_id The id of the object instance to find.
 * \return Pointer to the object instance if it was found.
 *         NULL If the object instance coulnd't be found.
 */
pt_object_instance_t *pt_devices_find_object_instance(const pt_devices_t *devices,
                                                      const char *device_id,
                                                      const uint16_t object_id,
                                                      const uint16_t object_instance_id);
/**
 * \brief Finds a resource from the device list given the device id, object id, object instance id and resource id.
 * \param devices Pointer to a valid device list. It may not be NULL.
 * \param device_id The device id.
 * \param object_id The id of the object to find.
 * \param object_instance_id The id of the object instance to find.
 * \param resource_id The id of the resource to find.
 * \return Pointer to the resource if it was found.
 *         NULL If the resource coulnd't be found.
 */
pt_resource_t *pt_devices_find_resource(const pt_devices_t *devices,
                                        const char *device_id,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id);

/**
 * \brief The client may use this from `received_write_cb()`. It calls the resource callback for write and execute
 * messages received from the Edge Core.
 *
 * The callback is run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param[in] connection_id The connection.
 * \param[in] device_id The device id receiving the write.
 * \param[in] object_id The object id of the object receiving the write.
 * \param[in] instance_id The object instance id of the object instance receiving the write.
 * \param[in] resource_id The resource id of the resource receiving the write.
 * \param[in] operation The operation on the resource. See `constants.h` for the defined values.
 * \param[in] value The argument byte buffer of the write operation.
 * \param[in] value_size The size of the value argument.
 * \param[in] userdata* Received userdata from write message.
 *
 * \return Returns `PT_STATUS_SUCCESS` on success and other error codes on failure.
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_devices_call_resource_callback(connection_id_t connection_id,
                                              const char *device_id,
                                              const uint16_t object_id,
                                              const uint16_t instance_id,
                                              const uint16_t resource_id,
                                              const unsigned int operation,
                                              const uint8_t *value,
                                              const uint32_t value_size);

#endif // PT_DEVICES_API_INTERNAL_H
