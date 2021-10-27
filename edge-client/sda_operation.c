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
#include "edge-client/sda_operation.h"
#include "edge-client/sda_helper.h"
#include "cs_hash.h"
#include "kcm_defs.h"

uint32_t message_size = 0;
static uint8_t* buffer = NULL;
uint8_t message_header[FTCD_MSG_HEADER_TOKEN_SIZE_BYTES] = FTCD_MSG_HEADER_TOKEN_SDA;

sda_protocol_error_t is_token_detected() {
	for (int i = 0; i < FTCD_MSG_HEADER_TOKEN_SIZE_BYTES; i++) {
		if (buffer[i] != message_header[i]) {
			return PT_ERR_HEADER_MISMATCH;
		}
	}
	return PT_ERR_OK;
}

uint32_t read_message_size() {
	uint32_t message_size = (buffer[8] << 24) + (buffer[9] << 16) +
							(buffer[10] << 8) + buffer[11];
	return message_size;
}
// read message which goes to SDA.
sda_protocol_error_t read_message(uint8_t* message, uint32_t message_size) {
	if (memcpy(message, &buffer[START_DATA], message_size) == NULL) {
		return PT_ERR_MSG;
	}
	return PT_ERR_OK;
}
sda_protocol_error_t read_message_signature(uint8_t* sig, size_t req_size) {
	if (memcpy(sig, &buffer[HEADER_BYTE + message_size + 1], req_size) == NULL) {
		return PT_ERR_MSG_SIG;
	}
	return PT_ERR_OK;
}

sda_protocol_error_t sda_client_request(uint8_t* request, uint8_t* response,
										size_t response_max_size,
										uint16_t* response_size) {
	buffer = request;
	size_t response_actual_size = 0;
	sda_protocol_error_t status = is_token_detected();
	if (status != PT_ERR_OK) {
		mbed_tracef(TRACE_LEVEL_ERROR, TRACE_GROUP_OP, "Token not detected");
		return status;
	}
	message_size = read_message_size();
	uint8_t* msg = (uint8_t*)malloc(message_size);
	if (msg == NULL) {
		tr_error("Can not init message to process SDA");
		return PT_ERR_MSG;
	}
	if (read_message(msg, message_size) != PT_ERR_OK) {
		tr_error("not able to get message %ld", message_size);
		free(msg);
		msg = NULL;
		buffer = NULL;
		return PT_ERR_MSG;
	}
	uint8_t sig_from_message[KCM_SHA256_SIZE];
	status = read_message_signature(sig_from_message, sizeof(sig_from_message));
	if (status != PT_ERR_OK) {
		tr_error("err reading message");
		free(msg);
		msg = NULL;
		buffer = NULL;
		return status;
	}
	bool success = process_request_fetch_response(msg, message_size, response, response_max_size, &response_actual_size);
	if (!success) {
		tr_error("Failed processing request message");
		free(msg);
		msg = NULL;
		buffer = NULL;
		return PT_ERR_PROCESS_REQ;
	}

	*response_size = response_actual_size;

	uint8_t self_calculated_sig[KCM_SHA256_SIZE] = {0};
	kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
	kcm_status = cs_hash(CS_SHA256, msg, message_size, self_calculated_sig,
						 sizeof(self_calculated_sig));
	if (kcm_status != KCM_STATUS_SUCCESS) {
		tr_error("Failed calculating message signature");
		status = PT_ERR_FAILED_TO_CALCULATE_MESSAGE_SIGNATURE;
		free(msg);
		msg = NULL;
		buffer = NULL;
		return status;
	}

	if (memcmp(self_calculated_sig, sig_from_message, KCM_SHA256_SIZE) != 0) {
		tr_error("Inconsistent message signature");
		status = PT_ERR_INCONSISTENT_MESSAGE_SIGNATURE;
		free(msg);
		return status;
	}
	free(msg);
	msg = NULL;
	buffer = NULL;
	return PT_ERR_OK;
}
#endif // SDA_WITH_EDGE