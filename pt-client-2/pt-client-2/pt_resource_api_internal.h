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

#ifndef PT_RESOURCE_API_INTERNAL_H
#define PT_RESOURCE_API_INTERNAL_H

#include "pt-client-2/pt_common_api.h"
#include "pt-client-2/pt_userdata_api.h"
#include "pt-client-2/pt_api_internal.h"

/**
 * \brief Used to set a value to the resource.
 *        To update the values to the Edge core call pt_devices_update.
 *        Note: if resource has a value already, it will be freed.
 * \param resource Pointer to a valid resource. May not be NULL.
 * \param value A pointer to the value buffer.\n
 *        The ownership of the value buffer is within the `pt_resource_t`.
 *        For different LwM2M data types there are byte-order restrictions as follows:\n
 *        \li \b String: UTF-8.
 *        \li \b Integer: A binary signed integer in network byte-order (64 bits).
 *        \li \b Float: IEEE 754-2008 floating point value in network byte-order (64 bits).
 *        \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *        \li \b Opaque: The sequence of binary data.
 *        \li \b Time: Same representation as integer.
 *        \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 * second is the Object Instance ID.\n Refer to: OMA Lightweight Machine to Machine Technical Specification for data
 * type specifications.
 * \param value_size The size of the value to write.
 * \param value_free_cb A callback function to free the value buffer that will be called when the resource is destroyed
 or a new value buffer is assigned.
 */
void pt_resource_set_value(pt_resource_t *resource,
                           const uint8_t *value,
                           const uint32_t value_size,
                           pt_resource_value_free_callback value_free_cb);

/**
 * \brief Used to get the value from the resource.
 * \param resource Pointer to a valid resource. May not be NULL.
 * \return value A pointer to the value buffer.\n
 *        The ownership of the value buffer is within the `pt_resource_t`.
 *        For different LwM2M data types there are byte-order restrictions as follows:\n
 *        \li \b String: UTF-8.
 *        \li \b Integer: A binary signed integer in network byte-order (64 bits).
 *        \li \b Float: IEEE 754-2008 floating point value in network byte-order (64 bits).
 *        \li \b Boolean: An 8 bit unsigned integer with value 0 or 1.
 *        \li \b Opaque: The sequence of binary data.
 *        \li \b Time: Same representation as integer.
 *        \li \b Objlnk: Two 16 bit unsigned integers one beside the other. The first one is the Object ID and the
 * second is the Object Instance ID.\n Refer to: OMA Lightweight Machine to Machine Technical Specification for data
 * type specifications.
 */
uint8_t *pt_resource_get_value(const pt_resource_t *resource);

/**
 * \brief Used to retrieve the next resource given the current resource.
 * \param resource Pointer to the current valid resource. It may not be NULL.
 * \return The next resource in the object instance's resource list. If there is no next resource, a NULL
 * will be returned.
 */
pt_resource_t *pt_resource_get_next(const pt_resource_t *resource);

#endif // PT_RESOURCE_API_INTERNAL_H
