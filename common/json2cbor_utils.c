/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
 */

#include "common/json2cbor_utils.h"
#include "mbed-trace/mbed_trace.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/base64.h>
#include <mbedtls/platform.h>
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

int pem_cert_to_der(const char *pem_path, unsigned char **der_buf, size_t *der_len)
{
    FILE *f = fopen(pem_path, "rb");
    if (!f)
    {
        tr_err("Unable to open certificate file: %s\n", pem_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char *pem_buf = malloc(fsize + 1);
    fread(pem_buf, 1, fsize, f);
    fclose(f);
    pem_buf[fsize] = '\0';

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    int ret = mbedtls_x509_crt_parse(&crt, pem_buf, fsize + 1);

    free(pem_buf);

    if (ret != 0)
    {
        tr_err("Failed to parse certificate (mbedtls_x509_crt_parse returned %d)\n", ret);
        mbedtls_x509_crt_free(&crt);
        return -1;
    }

    *der_len = crt.raw.len;
    *der_buf = malloc(*der_len);
    if (!*der_buf)
    {
        tr_err("Memory allocation failed\n");
        mbedtls_x509_crt_free(&crt);
        return -1;
    }

    memcpy(*der_buf, crt.raw.p, *der_len);
    mbedtls_x509_crt_free(&crt);
    return 0;
}

int pem_key_to_der(const char *pem_path, unsigned char **der_buf, size_t *der_len)
{
    FILE *f = fopen(pem_path, "rb");
    if (!f)
    {
        tr_err("Unable to open private key file: %s\n", pem_path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char *pem_buf = malloc(fsize + 1);
    fread(pem_buf, 1, fsize, f);
    fclose(f);
    pem_buf[fsize] = '\0';

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_key(&pk, pem_buf, fsize + 1, NULL, 0);
    free(pem_buf);

    if (ret != 0)
    {
        tr_err("Failed to parse private key (mbedtls_pk_parse_key returned %d)\n", ret);
        mbedtls_pk_free(&pk);
        return -1;
    }

    // Export to DER
    unsigned char buf[4096]; // adjust size as needed
    unsigned char *p = buf + sizeof(buf);
    size_t len = mbedtls_pk_write_key_der(&pk, buf, sizeof(buf));

    if (len <= 0)
    {
        tr_err("Failed to write DER private key\n");
        mbedtls_pk_free(&pk);
        return -1;
    }

    *der_buf = malloc(len);
    if (!*der_buf)
    {
        tr_err("Memory allocation failed\n");
        mbedtls_pk_free(&pk);
        return -1;
    }

    memcpy(*der_buf, p - len, len);
    *der_len = len;
    mbedtls_pk_free(&pk);
    return 0;
}

int load_pem_file(const char *path, uint8_t **out_buf, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    char *pem = malloc(fsize + 1);
    fread(pem, 1, fsize, f);
    pem[fsize] = '\0';
    fclose(f);

    // Find the base64 section
    char *begin = strstr(pem, "-----BEGIN");
    if (!begin)
    {
        free(pem);
        return -2;
    }
    begin = strchr(begin, '\n');
    if (!begin)
    {
        free(pem);
        return -3;
    }
    begin++;
    char *end = strstr(begin, "-----END");
    if (!end)
    {
        free(pem);
        return -4;
    }

    // Clean base64 and decode
    char *b64 = strndup(begin, end - begin);
    char *ptr = b64;
    size_t b64len = 0;
    for (char *p = b64; *p; ++p)
    {
        if (*p != '\n' && *p != '\r')
            b64[b64len++] = *p;
    }
    b64[b64len] = '\0';

    size_t olen = 0;
    size_t alloc_len = b64len * 3 / 4 + 1;
    uint8_t *bin = malloc(alloc_len);
    int ret = mbedtls_base64_decode(bin, alloc_len, &olen, (const unsigned char *)b64, b64len);
    free(b64);
    free(pem);

    if (ret != 0)
    {
        free(bin);
        return -5;
    }

    *out_buf = bin;
    *out_len = olen;
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