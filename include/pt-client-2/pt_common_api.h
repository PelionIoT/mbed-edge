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

#ifndef PT_COMMON_API_H
#define PT_COMMON_API_H

/**
 * \file pt-client-2/pt_common_api.h
 * \brief Contains common structures and definitions for the protocol translator client.
 */

#include <stdint.h>
#include "common/constants.h"
#include "common/default_message_id_generator.h"

typedef struct pt_api_mutex_s pt_api_mutex_t;
typedef int32_t connection_id_t;
#define PT_API_CONNECTION_ID_INVALID -1

typedef struct pt_client_data_s pt_client_t;

typedef enum { NONE, QUEUE } queuemode_t;

/**
 * \brief Enumeration containing the possible return status codes for Protocol API functions.
 */
typedef enum {
    PT_STATUS_SUCCESS = 0,
    PT_STATUS_ERROR,
    PT_STATUS_UNNECESSARY,
    PT_STATUS_ITEM_EXISTS,
    PT_STATUS_INVALID_PARAMETERS,
    PT_STATUS_ALLOCATION_FAIL,
    PT_STATUS_NOT_CONNECTED,
    PT_STATUS_NOT_FOUND,
    PT_STATUS_FEATURE_INITIALIZATION_FAIL
} pt_status_t;

/**
 * \brief Enumeration contain device registration states.
 */
typedef enum {
    PT_STATE_UNREGISTERED,
    PT_STATE_REGISTERING,
    PT_STATE_REGISTERED,
    PT_STATE_UNREGISTERING
} pt_device_state_e;

/**
 * \brief Enumeration contain device feature flags.
 */
typedef enum {
    PT_DEVICE_FEATURE_NONE = 0,
    PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL = (1 << 1),
} pt_device_feature_e;

#endif

