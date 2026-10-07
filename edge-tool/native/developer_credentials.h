/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_DEVELOPER_CREDENTIALS_H
#define EDGE_DEVELOPER_CREDENTIALS_H
#include <stddef.h>
#define EDGE_CREDENTIAL_FILE_LIMIT (1024u * 1024u)
/* Accept data declarations, never execute or compile the input C source.
 * On success, caller owns a secret CBOR buffer: cleanse it before freeing. */
int edge_convert_developer(const unsigned char *source, size_t length,
                           unsigned char **output, size_t *output_length,
                           const char **error);
#endif
