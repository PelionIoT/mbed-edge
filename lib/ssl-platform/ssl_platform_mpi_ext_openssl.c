#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL
#include "ssl_platform_mpi_ext.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix, char *buf, size_t buflen, size_t *olen) { if (radix != 16) return SSL_PLATFORM_ERROR_NOT_SUPPORTED; char *str = BN_bn2hex(X); if (!str) return SSL_PLATFORM_ERROR_GENERIC; *olen = strlen(str); if (*olen >= buflen) { OPENSSL_free(str); return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL; } strcpy(buf, str); OPENSSL_free(str); return SSL_PLATFORM_SUCCESS; }
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s) { if (radix != 16) return SSL_PLATFORM_ERROR_NOT_SUPPORTED; int ret = BN_hex2bn((BIGNUM**)int ret = BN_hex2bn(&X, s)X, s); return (ret > 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { return BN_cmp(X, Y); }
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z) { BIGNUM *bn_z = BN_new(); if (!bn_z) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION; BN_set_word(bn_z, abs(z)); int result = BN_cmp(X, bn_z); BN_free(bn_z); if (z < 0 && BN_is_zero(X) == 0) result = -result; return result; }
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { BIGNUM *ret = BN_copy(X, Y); return (ret == X) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val) { int ret = val ? BN_set_bit(X, pos) : BN_clear_bit(X, pos); return (ret == 1) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos) { return BN_is_bit_set(X, pos); }
#endif
