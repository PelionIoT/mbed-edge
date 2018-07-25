/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "rf"
#define RF_CHUNK 65536

int edge_read_file(const char* filename, uint8_t** data, size_t *read)
{
    if (!filename || !data || !read) {
        tr_err("Invalid parameters for read_file_content.");
        return 1;
    }

    FILE *f = fopen(filename, "r");
    if (f == NULL || ferror(f)) {
        if (f != NULL) {
            fclose(f);
        }
        tr_err("Cannot read file %s.", filename);
        return 1;
    }

    uint8_t *buffer = NULL;
    uint8_t *tmp;
    size_t size = 0;
    size_t used = 0;
    size_t n;

    while (1) {
        if (used + RF_CHUNK + 1 > size) {
            size = used + RF_CHUNK + 1;
        }

        if (size <= used) {
            free(buffer);
            fclose(f);
            tr_err("File read overflow.");
            return 1;
        }

        tmp = realloc(buffer, size);
        if(!tmp) {
            free(buffer);
            fclose(f);
            tr_err("Buffer reallocation error during file reading.");
            return 1;
        }
        buffer = tmp;

        n = fread(buffer + used, sizeof(uint8_t), RF_CHUNK, f);
        if (n == 0) {
            // No more to read.
            break;
        }
        used += n;
    }

    if (ferror(f)) {
        free(buffer);
        fclose(f);
        tr_err("File reading error.");
        return 1;
    }
    fclose(f);

    tmp = realloc(buffer, used + 1);
    if (!tmp) {
        free(buffer);
        tr_err("Reallocation error for read file content.");
        return 1;
    }
    buffer = tmp;
    buffer[used] = '\0';
    *data = buffer;
    *read = used;
    return 0;
}
