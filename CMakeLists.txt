#For Cmake system, if we want to compile all projects with cross toolchain. Then we should set the CMAKE_TOOLCHAIN_FILE as the 1st step.
#More information could be refered to here:
#https://gitlab.kitware.com/cmake/community/wikis/doc/cmake/CrossCompiling

# Check if user initialized and updated git submodules
if (NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/lib/libwebsockets/libwebsockets/CMakeLists.txt" OR
    NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/lib/jansson/jansson/CMakeLists.txt" OR
    NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/lib/libevent/libevent/CMakeLists.txt" OR
    NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/library" OR
    NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/crypto"
   )
	MESSAGE (FATAL_ERROR "Cannot find required libraries, please run \
                       `git submodule update --init --recursive`")
endif()

if (NOT DEFINED TARGET_TOOLCHAIN)
    SET (TARGET_TOOLCHAIN "mcc-linux-x86")
endif()
# Yocto build defines CMAKE_TOOLCHAIN_FILE to set the tool chain.
# We must not override it.
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if (DEFINED TARGET_CONFIG_ROOT)
        SET(CMAKE_TOOLCHAIN_FILE "${TARGET_CONFIG_ROOT}/toolchain.cmake")
    else ()
        SET(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/toolchains/mcc-linux-x86.cmake")
    endif()
endif()
project ("edge" C)
cmake_minimum_required (VERSION 3.5)

SET (EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

SET (TARGET_GROUP production CACHE STRING "Build target group")

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set (ROOT_HOME ${CMAKE_CURRENT_LIST_DIR})

find_package (Threads REQUIRED)

# Utility cmake functions
include (cmake/common.cmake)

# Edge basic configuration
include (cmake/edge_configure.cmake)

# Edge include directories
include (cmake/edge_include_directories.cmake)


include(git_details.cmake)

ADD_DEFINITIONS(-D__STDC_FORMAT_MACROS)
if (NOT (CMAKE_BUILD_TYPE STREQUAL Release))
    SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
    SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif ()

if (TARGET_GROUP STREQUAL test)
  SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-c++14-compat -g -fprofile-arcs -ftest-coverage")
  SET (CMAKE_EXE_LINKER_FLAGS "-fprofile-arcs")
  SET (CPPUTEST_HOME "${CMAKE_CURRENT_LIST_DIR}/lib/cpputest")
  add_subdirectory (test)
else ()
  if (ENABLE_COVERAGE EQUAL 1)
    message ("Enabling coverage")
    SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
    SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -lgcov")
  endif ()
  if (ENABLE_THREAD_SANITIZE EQUAL 1)
    message ("Enabling thread sanitizer")
    SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
    SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
  endif ()
endif ()

add_subdirectory (common)
add_subdirectory (nano-stack)
add_subdirectory (mbed-trace-edge)
add_subdirectory (edge-client)
add_subdirectory (lib)
add_subdirectory (edge-core)
add_subdirectory (edge-rpc)
add_subdirectory (pt-client)
add_subdirectory (pt-client-2)

# Add doc target for building documentation with Doxygen
# add a target to generate API documentation with Doxygen
find_package (Doxygen)
option (BUILD_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})
if (BUILD_DOCUMENTATION)
    if (NOT DOXYGEN_FOUND)
        message (FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif ()

    set (doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set (doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    configure_file (${doxyfile_in} ${doxyfile} @ONLY)

    add_custom_target (edge-doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
endif ()

