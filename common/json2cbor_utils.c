/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
 */

#include "common/json2cbor_utils.h"
#include "mbed-trace/mbed_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define TRACE_GROUP "json2cbor_utils"

// Helper: convert hex char to byte
static uint8_t _from_hex(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    return 0xFF; // invalid
}

int parse_hex_16(const char *hex, uint8_t *out)
{
    if (strlen(hex) != 32)
        return -1;
    for (int i = 0; i < 16; i++)
    {
        uint8_t high = _from_hex(hex[2 * i]);
        uint8_t low = _from_hex(hex[2 * i + 1]);
        if (high == 0xFF || low == 0xFF)
            return -2;
        out[i] = (high << 4) | low;
    }
    return 0;
}

int load_der_file(const char *path, uint8_t **out_buf, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    uint8_t *buf = malloc(fsize);
    fread(buf, 1, fsize, f);
    fclose(f);

    *out_buf = buf;
    *out_len = fsize;
    return 0;
}