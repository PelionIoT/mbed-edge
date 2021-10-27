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
#if defined(EDGE_ENABLE_SDA)

#include "edge-client/sda_helper.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "factory_configurator_client.h"
#include "key_config_manager.h"
#include "pal.h"
#include "sda_status.h"
#include "secure_device_access.h"

extern const uint8_t MBED_CLOUD_TRUST_ANCHOR_PK[];
extern const uint32_t MBED_CLOUD_TRUST_ANCHOR_PK_SIZE;
extern const char MBED_CLOUD_TRUST_ANCHOR_PK_NAME[];
size_t param_size = 0;

char *get_endpoint_name() {
	kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
	char *endpoint_name = NULL;
	size_t endpoint_buffer_size;
	size_t endpoint_name_size;
	// Get endpoint name data size
	kcm_status =
		kcm_item_get_data_size((const uint8_t *)g_fcc_endpoint_parameter_name,
							   strlen(g_fcc_endpoint_parameter_name),
							   KCM_CONFIG_ITEM, &endpoint_name_size);
	if (kcm_status != KCM_STATUS_SUCCESS) {
		tr_error("kcm_item_get_data_size failed (%u)", kcm_status);
		return NULL;
	}

	endpoint_buffer_size = endpoint_name_size + 1; /* for '\0' */

	endpoint_name = (char *)malloc(endpoint_buffer_size);
	memset(endpoint_name, 0, endpoint_buffer_size);
	kcm_status = kcm_item_get_data(
		(const uint8_t *)g_fcc_endpoint_parameter_name,
		strlen(g_fcc_endpoint_parameter_name), KCM_CONFIG_ITEM,
		(uint8_t *)endpoint_name, endpoint_name_size, &endpoint_name_size);
	if (kcm_status != KCM_STATUS_SUCCESS) {
		free(endpoint_name);
		tr_error("kcm_item_get_data failed (%u)", kcm_status);
		return NULL;
	}

	return endpoint_name;
}

bool process_request_fetch_response(const uint8_t *request,
									uint32_t request_size, uint8_t *response,
									size_t response_max_size,
									size_t *response_actual_size) {
	sda_status_e sda_status = SDA_STATUS_SUCCESS;
	// Call to sda_operation_process to process current message, the response
	// message will be returned as output.
	sda_status = sda_operation_process(request, request_size,
									   *application_callback, NULL, response,
									   response_max_size, response_actual_size);
	if (sda_status != SDA_STATUS_SUCCESS) {
		tr_error("Secure-Device-Access operation process failed (%u)",
				 sda_status);
	}

	if (*response_actual_size != 0) {
		return true;
	} else {
		return false;
	}
}

sda_status_e application_callback(sda_operation_ctx_h handle,
								  void *callback_param) {
	sda_status_e sda_status = SDA_STATUS_SUCCESS;
	sda_status_e sda_status_for_response = SDA_STATUS_SUCCESS;
	sda_command_type_e command_type = SDA_OPERATION_NONE;
	const uint8_t *func_callback_name;
	size_t func_callback_name_size;
	bool success = false;  // assume error

	char response[ResponseBufferLength] = {};
	sda_status = sda_command_type_get(handle, &command_type);
	if (sda_status != SDA_STATUS_SUCCESS) {
		tr_error("Secure-Device-Access failed getting command type (%u)",
				 sda_status);
		sda_status_for_response = sda_status;
		goto out;
	}

	// Currently only SDA_OPERATION_FUNC_CALL is supported
	if (command_type != SDA_OPERATION_FUNC_CALL) {
		tr_error("Got invalid command-type (%u)", command_type);
		sda_status_for_response = SDA_STATUS_INVALID_REQUEST;
		goto out;
	}

	func_callback_name = NULL;
	func_callback_name_size = 0;

	sda_status = sda_func_call_name_get(handle, &func_callback_name,
										&func_callback_name_size);
	if (sda_status != SDA_STATUS_SUCCESS) {
		tr_error(
			"Secure-Device-Access failed getting function callback name (%u)",
			sda_status);
		sda_status_for_response = sda_status;
		goto out;
	}

	tr_info("Function callback is %.*s", (int)func_callback_name_size,
			func_callback_name);

	// Check permission
	sda_status = is_operation_permitted(handle, func_callback_name,
										func_callback_name_size);
	if (sda_status != SDA_STATUS_SUCCESS) {
		tr_error("%.*s operation not permitted (%u)",
				 (int)func_callback_name_size, func_callback_name, sda_status);
		sda_status_for_response = sda_status;
		goto out;
	}

	/***
	* The following commands represents two demos as listed below:
	*   - MWC (Mobile World Congress):
	*     1. "configure"
	*     2. "read-data"
	*     3. "update"
	*
	*   - Hannover Mess:
	*     1. "diagnostics"
	*     2. "restart"
	*     3. "update"
	*
	*   - Note that "update" is a common command for both.
	*/
	/***
	* configure is the task to write the content coming in the SDA Request in
	* the file.
	* Function param that comes with "configure" request contains the data that
	* needed to write
	* as well as the path where the file will be written.
	*/
	
// flow succeeded
out:

	if ((sda_status_for_response != SDA_STATUS_SUCCESS) &&
		(sda_status_for_response != SDA_STATUS_NO_MORE_SCOPES)) {
		// Notify some fault happen (only if not 'access denied')
		tr_error("Bad Request");
	}

	return sda_status_for_response;
}

sda_status_e is_operation_permitted(sda_operation_ctx_h operation_context,
									const uint8_t *func_name,
									size_t func_name_size) {
	sda_status_e status;
	const uint8_t *scope;
	size_t scope_size;
	scope = NULL;
	scope_size = 0;

	// Get next available scope in list
	status = sda_scope_get_next(operation_context, &scope, &scope_size);

	// Check if end of scope list reached
	if (status == SDA_STATUS_NO_MORE_SCOPES) {
		tr_error("No match found for operation, permission denied");
		goto access_denied;
	}

	if (status != SDA_STATUS_SUCCESS) {
		tr_error("Failed getting scope, permission denied");
		goto access_denied;
	}

	if ((scope == NULL) || (scope_size == 0)) {
		tr_warn("Got empty or invalid scope, skipping this scope");
		return SDA_STATUS_NO_MORE_SCOPES;
	}

	// Check operation is in scope

	// Check that function name has the exact scope size
	if (scope_size != func_name_size) {
	}

	// Check that function name and scope are binary equal
	if (memcmp(func_name, scope, func_name_size) != 0) {
	}

	tr_info("Operation in scope, access granted");

	return SDA_STATUS_SUCCESS;  // operation permitted

access_denied:

	// Access denied

	tr_error("Operation not in scope, access denied");

	// display_faulty_message("Access Denied");

	return status;
}

bool factory_setup(void) {
#if MBED_CONF_APP_DEVELOPER_MODE == 1
	kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
#endif
	fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
	bool status = true;

	// In both of this cases we call fcc_verify_device_configured_4mbed_cloud()
	// to check if all data was provisioned correctly.

	// Initializes FCC to be able to call FCC APIs
	// TBD: SDA should be able to run without FCC init
	fcc_status = fcc_init();
	if (fcc_status != FCC_STATUS_SUCCESS) {
		status = false;
		tr_error("Failed to initialize Factory-Configurator-Client (%u)",
				 fcc_status);
		goto out;
	}

#if MBED_CONF_APP_DEVELOPER_MODE == 1
	// Storage delete
	fcc_status = fcc_storage_delete();
	if (fcc_status != FCC_STATUS_SUCCESS) {
		tr_error("Storage format failed (%u)", fcc_status);
		status = false;
		goto out;
	}
	// Call developer flow
	tr_cmdline("Start developer flow");
	fcc_status = fcc_developer_flow();
	if (fcc_status != FCC_STATUS_SUCCESS) {
		tr_error("fcc_developer_flow failed (%u)", fcc_status);
		status = false;
		goto out;
	}

	// Store trust anchor
	// Note: Until TA will be part of the developer flow.
	tr_info("Store trust anchor");
	kcm_status = kcm_item_store(
		(const uint8_t *)MBED_CLOUD_TRUST_ANCHOR_PK_NAME,
		strlen(MBED_CLOUD_TRUST_ANCHOR_PK_NAME), KCM_PUBLIC_KEY_ITEM, true,
		MBED_CLOUD_TRUST_ANCHOR_PK, MBED_CLOUD_TRUST_ANCHOR_PK_SIZE, NULL);
	if (kcm_status != KCM_STATUS_SUCCESS) {
		tr_error("kcm_item_store failed (%u)", kcm_status);
		status = false;
		goto out;
	}
#endif

	fcc_status = fcc_verify_device_configured_4mbed_cloud();
	if (fcc_status != FCC_STATUS_SUCCESS) {
		status = false;
		goto out;
	}

// Get endpoint name
// status = get_endpoint_name();
// if (status != true) {
//     tr_error("get_endpoint_name failed");
// }
out:
	// Finalize FFC
	fcc_status = fcc_finalize();
	if (status == false) {
		return false;
	} else {
		if (fcc_status != FCC_STATUS_SUCCESS) {
			tr_error("Failed finalizing Factory-Configurator-Client");
			return false;
		}
	}
	return status;
}
#endif // EDGE_ENABLE_SDA