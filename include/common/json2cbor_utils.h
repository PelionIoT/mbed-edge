/*
 * Copyright (c) 2025 Izuma Networks Inc
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
 */

#include <stdlib.h>
#include <stdint.h>

/**
 * @brief Load a DER file into memory.
 *
 * Reads the contents of a binary DER file and stores it in a buffer.
 *
 * @param[in]  path     Path to the DER file.
 * @param[out] out_buf  Pointer to the output buffer that will contain the file data.
 *                      Memory is allocated internally and must be freed by the caller.
 * @param[out] out_len  Pointer to the variable that will receive the length of the buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int load_der_file(const char *path, uint8_t **out_buf, size_t *out_len);

/**
 * @brief Parse a 16-character hexadecimal string into 8 bytes.
 *
 * Converts a hexadecimal string (e.g., "0123456789ABCDEF") into a binary buffer of 8 bytes.
 *
 * @param[in]  hex  Null-terminated string containing exactly 16 hexadecimal characters.
 * @param[out] out  Output buffer (must be at least 8 bytes) to hold the binary representation.
 *
 * @return 0 on success, -1 on failure (e.g., invalid length or characters).
 */
int parse_hex_16(const char *hex, uint8_t *out);
