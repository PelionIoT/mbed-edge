/*
 * SSL Platform Abstraction Layer - MPI Extensions
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SSL_PLATFORM_MPI_EXT_H
#define SSL_PLATFORM_MPI_EXT_H

#include "ssl_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Export X into a hexadecimal string
 *
 * \param X        Source MPI
 * \param radix    Output radix (only 16 is supported)
 * \param buf      Output buffer
 * \param buflen   Size of output buffer
 * \param olen     The number of bytes written to buf
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix,
                                   char *buf, size_t buflen, size_t *olen);

/**
 * \brief          Import X from a hexadecimal string
 *
 * \param X        Destination MPI
 * \param radix    Input radix (only 16 is supported)
 * \param s        Input string
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand side MPI
 * \param Y        Right-hand side MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser than Y or
 *                 0 if X is equal to Y
 */
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand side MPI
 * \param z        Right-hand side int
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser than z or
 *                 0 if X is equal to z
 */
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z);

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y);

/**
 * \brief          Set bit to a specific value
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit to modify
 * \param val      Desired value of the bit (0 or 1)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val);

/**
 * \brief          Get a specific bit from X
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit to query
 *
 * \return         0 or 1 on success, negative on error
 */
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos);

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_MPI_EXT_H */

int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos);
