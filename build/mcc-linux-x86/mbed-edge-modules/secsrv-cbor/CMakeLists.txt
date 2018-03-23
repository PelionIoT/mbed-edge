


project(secsrv-cbor)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor")


# recurse into dependencies that aren't built elsewhere



# And others (typically CMSIS implementations) need to export non-system header
# files. Please don't use this facility. Please. It's much, much better to fix
# implementations that import these headers to import them using the full path.
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/secsrv-cbor")


# modules with custom CMake build systems may append to the
# MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS property to add compile-time-determined include
# directories:
get_property(GLOBAL_INCLUDE_DIRS GLOBAL PROPERTY MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS)
include_directories(${GLOBAL_INCLUDE_DIRS})

# Provide versions of all the components we depend on, the corresponding
# preprocessor definitions are generated in mbed_edge_config.h
set(MBED_EDGE_BUILD_SECSRV_CBOR_VERSION_STRING "0.0.0")
set(MBED_EDGE_BUILD_SECSRV_CBOR_VERSION_MAJOR 0)
set(MBED_EDGE_BUILD_SECSRV_CBOR_VERSION_MINOR 0)
set(MBED_EDGE_BUILD_SECSRV_CBOR_VERSION_PATCH 0)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME secsrv-cbor)

# recurse into subdirectories for this component, using the two-argument
# add_subdirectory because the directories referred to here exist in the source
# tree, not the working directory
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/secsrv-cbor/source"
    "${CMAKE_BINARY_DIR}/mbed-edge-modules/secsrv-cbor/source"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(secsrv-cbor PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=secsrv-cbor")

# include .cmake files provided by the target:
