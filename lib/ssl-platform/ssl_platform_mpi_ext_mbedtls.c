#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
#include "ssl_platform_mpi_ext.h"
#include "mbedtls/bignum.h"
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix, char *buf, size_t buflen, size_t *olen) {
    int ret = mbedtls_mpi_write_string(X, radix, buf, buflen, olen);
    return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC;
}
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s) {
    int ret = mbedtls_mpi_read_string(X, radix, s); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { return mbedtls_mpi_cmp_mpi(X, Y); }
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z) { return mbedtls_mpi_cmp_int(X, z); }
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y) { int ret = mbedtls_mpi_copy(X, Y); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val) { int ret = mbedtls_mpi_set_bit(X, pos, val); return (ret == 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC; }
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos) { return mbedtls_mpi_get_bit(X, pos); }
#endif
