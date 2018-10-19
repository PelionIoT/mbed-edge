cmake_minimum_required(VERSION 2.6)

if(NOT DEFINED ENABLED_UNITY_TESTS)
    # disabled and compiled out tests if ENABLED_UNITY_TESTS variable not defined
	return()
endif()

# tests includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/runner)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/tests)

ADD_GLOBALDIR(${CMAKE_CURRENT_SOURCE_DIR}/../mock-utils)

set(TARGET_NAME "cec_tests")

FILE(
	GLOB_RECURSE
	cec_tests_src

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/runner/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/runner/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/runner/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cec_tests/tests/*.h"


	"${CMAKE_CURRENT_SOURCE_DIR}/../mock-utils/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/../mock-utils/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/../mock-utils/*.h"
)

message ("*********************************************************************")
message ("cec_tests_src = [[${cec_tests_src}]]")
message ("*********************************************************************")

CREATE_TEST_LIBRARY(${TARGET_NAME} "${cec_tests_src}" "")

ADDSUBDIRS()
