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

#ifndef PT_OBJECT_API_INTERNAL_H
#define PT_OBJECT_API_INTERNAL_H

#include "pt-client-2/pt_common_api.h"
#include "pt-client-2/pt_userdata_api.h"
#include "pt-client-2/pt_api_internal.h"

/**
 * \brief Finds an object instance from object.
 *
 * \param object The object.
 * \param id The object instance ID to find from the object.
 * \return The found object instance pointer or NULL.\n
 *         The ownership of the object instance is within the `pt_object_t`.
 */
pt_object_instance_t *pt_object_find_object_instance(const pt_object_t *object, const uint16_t id);

/**
 * \brief Used to return the device owning this object.
 * \param object Pointer to a valid object.
 * \return Pointer to object's device.
 */
pt_device_t *pt_object_get_parent(const pt_object_t *object);

/**
 * \brief Used to retrieve the next object given the current object.
 * \param object Pointer to the current valid object. It may not be NULL.
 * \return The next object in the device's object list. If there is no next object, a NULL will be returned.
 */
pt_object_t *pt_object_get_next(const pt_object_t *object);

/**
 * \brief Used to retrieve the first object instance of the object.
 * \param object Pointer to a valid object. It may not be NULL.
 * \return The first object instance in the object's object instance list.
 */
pt_object_instance_t *pt_object_first_object_instance(const pt_object_t *object);

/**
 * \brief Adds an object instance to an object.
 *
 * \param object The object to which to add the object instance.
 * \param id The object instance ID of the added object instance.
 * \param status A pointer to user provided variable for the operation status output. If an object instance was
 *               created, the status is set to `PT_STATUS_SUCCESS`.
 * \return The added empty object instance.\n
 *         The ownership of the returned object instance is within the `pt_object_t`.
 */
pt_object_instance_t *pt_object_add_object_instance_or_create(pt_object_t *object,
                                                              const uint16_t id,
                                                              pt_status_t *status);

/**
 * \brief Used to link some data to the object.
 * \param object Pointer to a valid object. It may not be NULL.
 * \param userdata Pointer to user data structure. Create it with `pt_api_create_userdata`.
 */
void pt_object_set_userdata(pt_object_t *object, pt_userdata_t *userdata);

#endif // PT_OBJECT_API_INTERNAL_H
