/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PT_CREDENTIAL_API_H
#define PT_CREDENTIAL_API_H
#include "pt-client-2/pt_crypto_api.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Wire helpers for the version 1 encrypted credential protocol. The caller
 * seals requests and authenticates responses as specified in credential-api.md.
 * Success buffers are borrowed until the callback returns. A fresh open resets
 * the connection's sequence and invalidates its previous challenge. */
pt_status_t pt_credential_open(connection_id_t connection,
    pt_crypto_success_handler success, pt_crypto_failure_handler failure, void *userdata);
pt_status_t pt_credential_request(connection_id_t connection, const char *namespace_name,
    uint64_t sequence, const uint8_t *envelope, size_t size,
    pt_crypto_success_handler success, pt_crypto_failure_handler failure, void *userdata);
#ifdef __cplusplus
}
#endif
#endif
