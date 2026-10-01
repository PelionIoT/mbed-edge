/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_PLATFORM_H
#define EDGE_PLATFORM_H

#ifdef _WIN32
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MSVC's tokenizer has the same explicit state argument as strtok_r. */
#define strtok_r strtok_s

static inline int edge_asprintf(char **output, const char *format, ...)
{
    va_list args;
    va_list copy;
    *output = NULL;
    va_start(args, format);
    va_copy(copy, args);
    int size = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (size < 0) { va_end(args); return -1; }
    char *buffer = (char *)malloc((size_t)size + 1);
    if (!buffer) { va_end(args); return -1; }
    int written = vsnprintf(buffer, (size_t)size + 1, format, args);
    va_end(args);
    if (written != size) { free(buffer); return -1; }
    *output = buffer;
    return written;
}
#define asprintf edge_asprintf
#endif

#endif
