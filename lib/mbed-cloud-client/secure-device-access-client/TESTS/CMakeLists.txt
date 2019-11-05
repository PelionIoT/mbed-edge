# ----------------------------------------------------------------------------
# Copyright 2017-2019 ARM Ltd.
#  
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  
#     http://www.apache.org/licenses/LICENSE-2.0
#  
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

cmake_minimum_required(VERSION 2.6)

if(NOT DEFINED ENABLED_UNITY_TESTS)
    # disabled and compiled out tests if ENABLED_UNITY_TESTS variable not defined
	return()
endif()

# tests includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/runner)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/tests)

set(TARGET_NAME "sda_tests")

FILE(
	GLOB_RECURSE
	sda_tests_src

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/runner/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/runner/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/runner/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/sda_tests/tests/*.h"
)

message ("*********************************************************************")
message ("sda_tests_src = [[${sda_tests_src}]]")
message ("*********************************************************************")

CREATE_TEST_LIBRARY(${TARGET_NAME} "${sda_tests_src}" "")

ADDSUBDIRS()
