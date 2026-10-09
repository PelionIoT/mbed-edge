/* SPDX-License-Identifier: Apache-2.0 */
#include "edge-core/status_public.h"
#include <string.h>

bool edge_status_public_uri(const char *uri, char *result, size_t capacity)
{
    if (!result || !capacity) return false;
    result[0] = '\0';
    if (!uri) return false;
    const char *scheme_end = strstr(uri, "://");
    if (!scheme_end || scheme_end == uri) return false;
    for (const char *part = uri; part < scheme_end; ++part) {
        char c = *part;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (part != uri && ((c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'))))
            return false;
    }
    const char *authority = scheme_end + 3;
    const char *end = authority + strcspn(authority, "/?#");
    const char *host = authority;
    for (const char *part = authority; part < end; ++part) {
        if (*part == '@') host = part + 1;
    }
    size_t prefix = (size_t)(authority - uri);
    size_t host_length = (size_t)(end - host);
    if (!host_length || prefix + host_length >= capacity) return false;
    memcpy(result, uri, prefix);
    memcpy(result + prefix, host, host_length);
    result[prefix + host_length] = '\0';
    return true;
}
