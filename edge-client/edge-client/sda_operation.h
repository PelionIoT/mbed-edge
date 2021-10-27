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

#ifndef _SDA_OPERATION_H_
#define _SDA_OPERATION_H_

#include <stddef.h>
#include <stdint.h>

#define FTCD_MSG_HEADER_TOKEN_SDA \
	{ 0x6d, 0x62, 0x65, 0x64, 0x64, 0x62, 0x61, 0x70 }
#define FTCD_MSG_HEADER_TOKEN_SIZE_BYTES 8

#define HEADER_START 0
#define HEADER_BYTE 11
#define START_DATA 12
#define TRACE_GROUP_OP "sdao"

typedef enum  {
	PT_ERR_OK,
	PT_ERR_HEADER_MISMATCH,
	PT_ERR_MSG,
	PT_ERR_MSG_SIG,
	PT_ERR_FAILED_TO_CALCULATE_MESSAGE_SIGNATURE,
	PT_ERR_INCONSISTENT_MESSAGE_SIGNATURE,
	PT_ERR_PROCESS_REQ,
	PT_ERR_EMPTY_MSG,
	PT_ERR_NOT_INIT,
	PT_ERR_BAD_REQ,
	PT_ERR_SEND_BLE,
	PT_ERR_WRITE_BLE,
	PT_ERR_SDA_REQ,
	PT_ERR_LOST_CONN,
	PT_ERR_BUFF_OVERFLOW,
	PT_ERR_MEM,
 } sda_protocol_error_t;

sda_protocol_error_t sda_client_request(uint8_t* request, uint8_t* response, size_t response_max_size, uint16_t* response_size);
sda_protocol_error_t sda_is_token_detected();
uint32_t read_message_size();
sda_protocol_error_t read_message(uint8_t* message, uint32_t message_size);
sda_protocol_error_t read_message_signature(uint8_t* message,
											size_t message_size);


#endif // _SDA_OPERATION_H_
#endif // EDGE_ENABLE_SDA