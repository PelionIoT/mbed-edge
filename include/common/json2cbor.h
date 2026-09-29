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
 * @brief Convert a JSON file to CBOR format in memory.
 *
 * This function reads a JSON file from disk, parses it, and encodes it into CBOR format.
 *
 * @param[in]  input_path Path to the input JSON file.
 * @param[out] out_buf    Pointer to the output buffer that will contain the CBOR-encoded data.
 *                        Memory is allocated internally and must be freed by the caller.
 * @param[out] buf_size   Pointer to the variable that will receive the size of the output buffer.
 *
 * @return 0 on success, -1 on failure (e.g., file I/O error or JSON parsing failure).
 */
int json_to_cbor(const char *input_path, uint8_t **out_buf, size_t *buf_size);
