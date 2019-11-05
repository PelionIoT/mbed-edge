cmake_minimum_required(VERSION 2.6)

if(NOT DEFINED ENABLED_UNITY_TESTS)
    # disabled and compiled out tests if ENABLED_UNITY_TESTS variable not defined
	return()
endif()

# tests includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/runner)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/tests)

set(TARGET_NAME "cose_tests")

FILE(
	GLOB_RECURSE  
	cose_tests_src

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/runner/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/runner/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/runner/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/unity-tests/cose_tests/tests/*.h"
)

message ("*********************************************************************")
message ("cose_tests_src = [[${cose_tests_src}]]")
message ("*********************************************************************")


CREATE_TEST_LIBRARY(${TARGET_NAME} "${cose_tests_src}" "")

ADDSUBDIRS()
