


project(mbedtls)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbedtls")


# recurse into dependencies that aren't built elsewhere




# modules with custom CMake build systems may append to the
# MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS property to add compile-time-determined include
# directories:
get_property(GLOBAL_INCLUDE_DIRS GLOBAL PROPERTY MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS)
include_directories(${GLOBAL_INCLUDE_DIRS})

# Provide versions of all the components we depend on, the corresponding
# preprocessor definitions are generated in mbed_edge_config.h
set(MBED_EDGE_BUILD_MBEDTLS_VERSION_STRING "2.4.1")
set(MBED_EDGE_BUILD_MBEDTLS_VERSION_MAJOR 2)
set(MBED_EDGE_BUILD_MBEDTLS_VERSION_MINOR 4)
set(MBED_EDGE_BUILD_MBEDTLS_VERSION_PATCH 1)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME mbedtls)

# recurse into subdirectories for this component, using the two-argument
# add_subdirectory because the directories referred to here exist in the source
# tree, not the working directory
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/mbedtls/source"
    "${CMAKE_BINARY_DIR}/mbed-edge-modules/mbedtls/source"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(mbedtls PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=mbedtls")

# include .cmake files provided by the target:
