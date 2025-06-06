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
)

# Backend-specific source files and dependencies
if(SSL_PLATFORM_BACKEND EQUAL 1)
    message(STATUS "SSL Platform: Using mbed-TLS backend")
    
    # mbed-TLS backend sources
    set(SSL_PLATFORM_SOURCES
        ${SSL_PLATFORM_COMMON_SOURCES}
        ssl_platform_mbedtls.h
        ssl_platform_mbedtls.c
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