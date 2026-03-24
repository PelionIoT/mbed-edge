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
 * @brief Convert a PEM certificate file to DER format in memory.
 *
 * This function reads a PEM-encoded X.509 certificate from a file and converts it to DER format.
 *
 * @param[in]  pem_path Path to the PEM certificate file.
 * @param[out] der_buf  Pointer to the output buffer that will hold the DER-encoded data.
 *                      Memory is allocated internally and must be freed by the caller.
 * @param[out] der_len  Pointer to the variable that will receive the length of the DER buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int pem_cert_to_der(const char *pem_path, unsigned char **der_buf, size_t *der_len);

/**
 * @brief Convert a PEM private key file to DER format in memory.
 *
 * This function reads a PEM-encoded private key from a file and converts it to DER format.
 *
 * @param[in]  pem_path Path to the PEM private key file.
 * @param[out] der_buf  Pointer to the output buffer that will hold the DER-encoded key.
 *                      Memory is allocated internally and must be freed by the caller.
 * @param[out] der_len  Pointer to the variable that will receive the length of the DER buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int pem_key_to_der(const char *pem_path, unsigned char **der_buf, size_t *der_len);

/**
 * @brief Load a PEM file into memory.
 *
 * Reads the contents of a PEM file and stores it in a buffer.
 *
 * @param[in]  path     Path to the PEM file.
 * @param[out] out_buf  Pointer to the output buffer that will contain the file data.
 *                      Memory is allocated internally and must be freed by the caller.
 * @param[out] out_len  Pointer to the variable that will receive the length of the buffer.
 *
 * @return 0 on success, -1 on failure.
 */
int load_pem_file(const char *path, uint8_t **out_buf, size_t *out_len);

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
