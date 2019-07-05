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

#include "nanostack-event-loop/eventOS_event.h"

typedef enum {
    CRYPTO_API_EVENT_INIT,
    CRYPTO_API_EVENT_GET_CERTIFICATE,
    CRYPTO_API_EVENT_GET_PUBLIC_KEY,
    CRYPTO_API_EVENT_GENERATE_RANDOM,
    CRYPTO_API_EVENT_ASYMMETRIC_SIGN,
    CRYPTO_API_EVENT_ASYMMETRIC_VERIFY,
    CRYPTO_API_EVENT_ECDH_KEY_AGREEMENT
} crypto_api_event_e;

#ifdef BUILD_TYPE_TEST
void crypto_api_event_handler(arm_event_t *event);
extern int8_t crypto_api_tasklet_id;
#endif

