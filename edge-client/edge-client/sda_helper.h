/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 Pelion Ltd.
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

#ifndef __SDAHELPER_H__
#define __SDAHELPER_H__

#include "factory_configurator_client.h"
#include "factory_configurator_client.h"
#include "key_config_manager.h"
#include "key_config_manager.h"
#include "pal.h"
#include "pal.h"
#include "sda_status.h"
#include "secure_device_access.h"

#define ResponseBufferLength 	1536
#define PathLength 				60
#define TRACE_GROUP 			"sdah"

bool factory_setup(void);
sda_status_e is_operation_permitted(sda_operation_ctx_h operation_context,
									const uint8_t *func_name,
									size_t func_name_size);
sda_status_e application_callback(sda_operation_ctx_h handle,
								  void *callback_param);
bool process_request_fetch_response(const uint8_t *request,
									uint32_t request_size, uint8_t *response,
									size_t response_max_size,
									size_t *response_actual_size);
char *get_endpoint_name();
#endif
