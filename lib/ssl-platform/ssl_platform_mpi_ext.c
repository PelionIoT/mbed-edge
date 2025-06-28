#include "ssl_platform.h"
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
#include "ssl_platform.h"
#include "ssl_platform_mpi_ext.h"
#include "mbedtls/bignum.h"
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix, char *buf, size_t buflen, size_t *olen) {
    int ret = mbedtls_mpi_write_string(&X->mbedtls_mpi, radix, buf, buflen, olen);
    return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC;
}
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s) {
    int ret = mbedtls_mpi_read_string(&X->mbedtls_mpi, radix, s); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { return mbedtls_mpi_cmp_mpi(&X->mbedtls_mpi, &Y->mbedtls_mpi); }
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z) { return mbedtls_mpi_cmp_int(&X->mbedtls_mpi, z); }
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { int ret = mbedtls_mpi_copy(&X->mbedtls_mpi, &Y->mbedtls_mpi); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val) { int ret = mbedtls_mpi_set_bit(&X->mbedtls_mpi, pos, val); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos) { return mbedtls_mpi_get_bit(&X->mbedtls_mpi, pos); }
#endif
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL
#include "ssl_platform_mpi_ext.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix, char *buf, size_t buflen, size_t *olen) { if (radix != 16) return SSL_PLATFORM_ERROR_NOT_SUPPORTED; char *str = BN_bn2hex(X->bn); if (!str) return SSL_PLATFORM_ERROR_GENERIC; *olen = strlen(str); if (*olen >= buflen) { OPENSSL_free(str); return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL; } strcpy(buf, str); OPENSSL_free(str); return SSL_PLATFORM_SUCCESS; }
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s) { if (radix != 16) return SSL_PLATFORM_ERROR_NOT_SUPPORTED; int ret = BN_hex2bn(&X->bn, s); return (ret > 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { return BN_cmp(X->bn, Y->bn); }
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z) { BIGNUM *bn_z = BN_new(); if (!bn_z) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION; BN_set_word(bn_z, abs(z)); int result = BN_cmp(X->bn, bn_z); BN_free(bn_z); if (z < 0 && BN_is_zero(X->bn) == 0) result = -result; return result; }
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { BIGNUM *ret = BN_copy(X->bn, Y->bn); return (ret == X->bn) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val) { int ret = val ? BN_set_bit(X->bn, pos) : BN_clear_bit(X->bn, pos); return (ret == 1) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos) { return BN_is_bit_set(X->bn, pos); }
#endif
