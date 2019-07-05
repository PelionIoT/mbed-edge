/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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

#ifndef PT_CRYPTO_API_INTERNAL_H
#define PT_CRYPTO_API_INTERNAL_H

#include <jansson.h>

#ifdef BUILD_TYPE_TEST

void pt_crypto_success_with_data(json_t *response, void *callback_data, const char *json_key);
void pt_crypto_success(json_t *response, void *callback_data);
void pt_handle_pt_crypto_get_public_key_success(json_t *response, void *callback_data);
void pt_handle_pt_crypto_get_certificate_success(json_t *response, void *callback_data);
void pt_handle_pt_crypto_get_item_failure(json_t *response, void *callback_data);

#endif // BUILD_TYPE_TEST

#endif // PT_CRYPTO_API_INTERNAL_H
