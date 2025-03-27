/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
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
