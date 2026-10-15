/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_STATUS_PUBLIC_H
#define EDGE_STATUS_PUBLIC_H
#include <stdbool.h>
#include <stddef.h>

#define EDGE_STATUS_MAX_JSON 65536u

bool edge_status_public_uri(const char *uri, char *result, size_t capacity);
#endif
