#################################################################################
#  Copyright 2020 ARM Ltd.
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


SET(TLS_LIBRARY mbedTLS)
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fomit-frame-pointer")
SET(ENABLE_PROGRAMS OFF CACHE STRING "Avoid compiling mbedtls programs" )
SET(ENABLE_TESTING OFF CACHE STRING "Avoid compiling mbedtls tests")

include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/include")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/include/mbedtls")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/port/ksdk")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/include/psa")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/include/mbedtls")
include_directories ("${CMAKE_SOURCE_DIR}/lib/mbedtls/library")

message(status "device = ${PAL_TARGET_DEVICE}")
set (EXTRA_CMAKE_DIRS ${EXTRA_CMAKE_DIRS} "${CMAKE_SOURCE_DIR}/lib/mbedtls")

list (APPEND SRC_LIBS mbedtls mbedcrypto mbedx509)

