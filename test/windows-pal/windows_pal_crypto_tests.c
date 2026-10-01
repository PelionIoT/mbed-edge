/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "cs_pal_plat_crypto.h"

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "Crypto test line %d: %s failed\n", __LINE__, #value); exit(1); \
} } while (0)
#define OK(value) CHECK((value) == FCC_PAL_SUCCESS)

/* Legacy entropy hook required by the shared source, using the real HAL. */
extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *, size_t, size_t *);
palStatus_t pal_osRandomBuffer(uint8_t *buffer, size_t size)
{
    size_t actual;
    return pal_plat_getRandomBufferFromHW(buffer, size, &actual);
}

int main(void)
{
    /* SHA-256("abc") and RFC 4231 HMAC-SHA-256 test case 1. */
    static const unsigned char sha256[] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    static const unsigned char hmac[] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    unsigned char output[32], key[20], random1[32], random2[32];
    size_t output_size;
    palCtrDrbgCtxHandle_t random = 0;
    puts(OpenSSL_version(OPENSSL_VERSION));
    OK(pal_plat_initCrypto());
    OK(pal_plat_sha256((const unsigned char *)"abc", 3, output));
    CHECK(memcmp(output, sha256, sizeof(output)) == 0);
    memset(key, 0x0b, sizeof(key));
    output_size = sizeof(output);
    OK(pal_plat_mdHmacSha256(key, sizeof(key), (const unsigned char *)"Hi There", 8, output, &output_size));
    CHECK(output_size == sizeof(hmac) && memcmp(output, hmac, sizeof(hmac)) == 0);
    OK(pal_plat_CtrDRBGInit(&random));
    OK(pal_plat_CtrDRBGGenerate(random, random1, sizeof(random1)));
    OK(pal_plat_CtrDRBGGenerate(random, random2, sizeof(random2)));
    CHECK(memcmp(random1, random2, sizeof(random1)) != 0);
    OK(pal_plat_CtrDRBGFree(&random));
    OK(pal_plat_cleanupCrypto());
    puts("PASS shared OpenSSL crypto: SHA-256, HMAC-SHA-256 and RAND_bytes");
    return 0;
}
