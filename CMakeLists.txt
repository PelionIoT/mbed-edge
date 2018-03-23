project ("mbed-edge" C)
cmake_minimum_required (VERSION 2.8)

SET (EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

SET (TARGET_GROUP production CACHE STRING "Build target group")

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


set (ROOT_HOME ${CMAKE_CURRENT_LIST_DIR})


include(git_details.cmake)

ADD_DEFINITIONS(-D__STDC_FORMAT_MACROS)
SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic -Wall -DDEBUG -g -std=gnu99")

# Mbed Edge include hierarchy
include_directories (include)
include_directories (common)
include_directories (edge-client)

include_directories (lib/jsonrpc)
include_directories (lib/fstrm/fstrm)
include_directories (lib/fstrm)

include_directories (mbed-edge-module-sources/mbed-trace)
include_directories (mbed-edge-module-sources/nanostack-libservice/mbed-client-libservice/)
include_directories (mbed-edge-module-sources/nanostack-libservice)

if (TARGET_GROUP STREQUAL test)
  SET (CMAKE_C_FLAGS "-Wall -g -O0 -fprofile-arcs -ftest-coverage")
  SET (CMAKE_CXX_FLAGS "-Wall -Wno-c++14-compat -g -O0 -fprofile-arcs -ftest-coverage")
  SET (CMAKE_EXE_LINKER_FLAGS "-fprofile-arcs")
  SET (CPPUTEST_HOME "${CMAKE_CURRENT_LIST_DIR}/lib/cpputest")
  add_subdirectory (test)
else ()
  if ("$ENV{ENABLE_COVERAGE}" EQUAL 1)
    message ("Enabling coverage")
    SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
    SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -fprofile-arcs -ftest-coverage")
    SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -lgcov")
  endif ()
endif ()

add_subdirectory (edge-client)
add_subdirectory (lib)
add_subdirectory (edge-core)
add_subdirectory (edge-rpc)
add_subdirectory (pt-client)
add_subdirectory (pt-example)

# Conditionally build lora-pt if mosquitto is available
unset(MOSQUITTO_LIB CACHE)
find_library(MOSQUITTO_LIB mosquitto)
if (SKIP_LIB_CHECK OR MOSQUITTO_LIB OR MBED_EDGE_BUILD_CFG_SKIP_LIB_CHECK)
  add_subdirectory (lorapt-example)
else ()
  message("Not building the mqtt protocol translator since mosquitto library was not found!")
endif ()

add_definitions (-DMBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE=102400)


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

    add_custom_target (doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
endif ()



file (GLOB EDGE_CORE_SOURCES ./edge-core/*.c)
file (GLOB CLIENT_SOURCES ./pt-client/*.c)
file (GLOB EXAMPLE_SOURCES ./pt-example/*.c)
add_library (mbed-edge-internal STATIC ${CLIENT_SOURCES} ${EDGE_CORE_SOURCES})
