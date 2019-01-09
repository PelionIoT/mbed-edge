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

#ifndef PT_USERDATA_API_H
#define PT_USERDATA_API_H

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

/**
 * \file pt-client-2/pt_userdata_api.h
 * \brief Protocol translator API for client's data.
 *
 * Functions in this file may be used to set user data to devices and resources. A free callback needs to be provided.
 * It's called automatically when the objects containing user data are deleted.
 */

struct pt_userdata_s;

/**
 * \brief The user-supplied memory deallocation function for userdata.
 *
 * \param[in] data The user-supplied data to free.
 */
typedef void (*pt_userdata_free_cb_t)(void *data);

/**
 * \brief Contains fields for client user data.
 *
 * If the client wants to associate data with the device or any object, this structure may be used.
 * Create it using pt_api_create_userdata.
 * The PT API will deallocate this structure and call the pt_free_userdata call-back when the object
 * structure is destroyed. However the client is responsible to free the pt_userdata_t#data using the
 * pt_userdata_t#pt_free_userdata call-back or in some other way.
 */
typedef struct pt_userdata_s {
    void *data;                             /**< Pointer to client's data that may be associated with the device. */
    pt_userdata_free_cb_t pt_free_userdata; /**< Points to customer implementation to free the userdata. */
} pt_userdata_t;

/**
 * \brief Used to create the pt_userdata_s structure.
 *
 * \param[in] data Pointer to client's data to associate.
 * \param[in] free_userdata_cb Pointer to function which will be called to free the data.
 *                         NULL value is allowed. In this case no user data free
 *                         function will be called. It's possible that there is no need
 *                         to deallocate the data.
 * \return pointer to `pt_userdata_t` if memory allocation succeeds.
 *         NULL if memory allocation fails. In this case implementation calls `free_userdata_cb` immediately
 *         if applicable and frees the pt_userdata_t#data.
 */
pt_userdata_t *pt_api_create_userdata(void *data, pt_userdata_free_cb_t free_userdata_cb);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif
