#################################################################################
#  Copyright 2024
#  
#  SPDX-License-Identifier: Apache-2.0
#  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#      http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#################################################################################

cmake_minimum_required(VERSION 3.5)

project(ssl-platform C)

# SSL Platform Backend Selection
# Set SSL_PLATFORM_BACKEND to choose backend:
#   1 = mbed-TLS (default)
#   2 = OpenSSL
if(NOT DEFINED SSL_PLATFORM_BACKEND)
    set(SSL_PLATFORM_BACKEND 1 CACHE STRING "SSL Platform Backend (1=mbed-TLS, 2=OpenSSL)")
endif()

# Validate backend selection
if(NOT (SSL_PLATFORM_BACKEND EQUAL 1 OR SSL_PLATFORM_BACKEND EQUAL 2))
    message(FATAL_ERROR "Invalid SSL_PLATFORM_BACKEND value: ${SSL_PLATFORM_BACKEND}. Must be 1 (mbed-TLS) or 2 (OpenSSL)")
endif()

# Common source files
set(SSL_PLATFORM_COMMON_SOURCES
    ssl_platform.h
    ssl_platform_compat.h
    ssl_platform_mpi_ext.h
)

# Backend-specific source files and dependencies
if(SSL_PLATFORM_BACKEND EQUAL 1)
    message(STATUS "SSL Platform: Using mbed-TLS backend")
    
    # mbed-TLS backend sources
    set(SSL_PLATFORM_SOURCES
        ${SSL_PLATFORM_COMMON_SOURCES}
        ssl_platform_mbedtls.h
        ssl_platform_mbedtls.c
        ssl_platform_mpi_ext.h
        ssl_platform_mpi_ext.c
    )
    
    # mbed-TLS include directories
    include_directories(${CMAKE_SOURCE_DIR}/lib/mbedtls/include)
    include_directories(${CMAKE_SOURCE_DIR}/lib/mbedtls/include/mbedtls)
    
    # Link to mbed-TLS libraries
    set(SSL_PLATFORM_LIBRARIES mbedtls mbedcrypto mbedx509)
    
elseif(SSL_PLATFORM_BACKEND EQUAL 2)
    message(STATUS "SSL Platform: Using OpenSSL backend")
    
    # Find OpenSSL
    find_package(OpenSSL REQUIRED)
    
    # OpenSSL backend sources
    set(SSL_PLATFORM_SOURCES
        ${SSL_PLATFORM_COMMON_SOURCES}
        ssl_platform_openssl.h
        ssl_platform_openssl.c
        ssl_platform_mpi_ext.h
        ssl_platform_mpi_ext.c
    )
    
    # OpenSSL include directories
    include_directories(${OPENSSL_INCLUDE_DIR})
    
    # Link to OpenSSL libraries
    set(SSL_PLATFORM_LIBRARIES ${OPENSSL_LIBRARIES})
    
endif()

# Create ssl-platform static library
add_library(ssl-platform STATIC ${SSL_PLATFORM_SOURCES})

# Set target properties
set_target_properties(ssl-platform PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# Compiler definitions - use target_compile_definitions for proper propagation
target_compile_definitions(ssl-platform PUBLIC
    SSL_PLATFORM_BACKEND=${SSL_PLATFORM_BACKEND}
)

# Link backend-specific libraries
target_link_libraries(ssl-platform PUBLIC ${SSL_PLATFORM_LIBRARIES})

# Include directories for the library
target_include_directories(ssl-platform PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Installation
install(TARGETS ssl-platform
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES
    ssl_platform.h
    ssl_platform_compat.h
    ssl_platform_mpi_ext.h
    DESTINATION include/ssl-platform
)

if(SSL_PLATFORM_BACKEND EQUAL 1)
    install(FILES
        ssl_platform_mbedtls.h
        DESTINATION include/ssl-platform
    )
elseif(SSL_PLATFORM_BACKEND EQUAL 2)
    install(FILES
        ssl_platform_openssl.h
        DESTINATION include/ssl-platform
    )
endif()

# Optional: Add test targets
option(SSL_PLATFORM_BUILD_TESTS "Build SSL Platform tests" ON)

if(SSL_PLATFORM_BUILD_TESTS)
    # AES CTR test
    add_executable(test_aes_ctr test_aes_ctr.c)
    target_link_libraries(test_aes_ctr ssl-platform)
    
    # X.509 and CTR-DRBG functions test
    add_executable(test_x509_functions test_x509_functions.c)
    target_link_libraries(test_x509_functions ssl-platform)
    
    # ECC and MPI functions test
    add_executable(test_ecc_mpi test_ecc_mpi.c)
    target_link_libraries(test_ecc_mpi ssl-platform)
    
    # CMAC operations test
    add_executable(test_cmac test_cmac.c)
    target_link_libraries(test_cmac ssl-platform)
    
    # CMAC integration test
    add_executable(test_cmac_integration test_cmac_integration.c)
    target_link_libraries(test_cmac_integration ssl-platform)
    
    # CCM test
    add_executable(test_ccm test_ccm.c)
    target_link_libraries(test_ccm ssl-platform)
    
    # SNI test
    add_executable(test_sni test_sni.c)
    target_link_libraries(test_sni ssl-platform)
    
    # Add tests to CTest if enabled
    if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
        include(CTest)
        if(BUILD_TESTING)
            add_test(NAME test_aes_ctr COMMAND test_aes_ctr)
            add_test(NAME test_x509_functions COMMAND test_x509_functions)
            add_test(NAME test_ecc_mpi COMMAND test_ecc_mpi)
            add_test(NAME test_cmac COMMAND test_cmac)
            add_test(NAME test_ccm COMMAND test_ccm)
            add_test(NAME test_sni COMMAND test_sni)
        endif()
    endif()
    
    message(STATUS "SSL Platform tests will be built: test_aes_ctr, test_x509_functions, test_ecc_mpi, test_cmac, test_ccm, test_sni")
endif()

# Optional: Add test subdirectory if it exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests" AND IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    add_subdirectory(tests)
endif()

# Print configuration summary
message(STATUS "SSL Platform Configuration:")
if(SSL_PLATFORM_BACKEND EQUAL 1)
    message(STATUS "  Backend: ${SSL_PLATFORM_BACKEND} (mbed-TLS)")
else()
    message(STATUS "  Backend: ${SSL_PLATFORM_BACKEND} (OpenSSL)")
endif()
message(STATUS "  Libraries: ${SSL_PLATFORM_LIBRARIES}")
message(STATUS "  Sources: ${SSL_PLATFORM_SOURCES}") 