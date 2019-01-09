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

#ifndef PT_OBJECT_INSTANCE_API_INTERNAL_H
#define PT_OBJECT_INSTANCE_API_INTERNAL_H

#include "pt-client-2/pt_common_api_internal.h"
#include "pt-client-2/pt_resource_api_internal.h"

/**
 * \brief Finds a resource from an object instance.
 *
 * \param instance The object instance.
 * \param id The resource ID to find from the object instance.
 * \return The found resource pointer or NULL.\n
 *         The ownership of the resource is within the `pt_object_instance_t`.
 */
pt_resource_t *pt_object_instance_find_resource(const pt_object_instance_t *instance, const uint16_t id);

/**
 * \brief Used to retrieve the user data from the object instance.
 * \param object_instance  Pointer to a valid object instance. It may not be NULL.
 * \return A pointer to the user data structure.
 */
pt_userdata_t *pt_object_instance_userdata(const pt_object_instance_t *object);

/**
 * \brief Used to retrieve the next object instance given the current object instance.
 * \param object_instance Pointer to the current valid object instance. It may not be NULL.
 * \return The next object instance in the object's object instance list. If there is no next object instance, a NULL
 * will be returned.
 */
pt_object_instance_t *pt_object_instance_get_next(const pt_object_instance_t *object_instance);

/**
 * \brief Used to retrieve the first resource of the object instance.
 * \param object_instance Pointer to a valid object instance. It may not be NULL.
 * \return The first resource in the object instance's resource list.
 */
pt_resource_t *pt_object_instance_first_resource(const pt_object_instance_t *object_instance);

#endif // PT_OBJECT_INSTANCE_API_INTERNAL_H
