


project(ns-hal-pal)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbedtls")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-trace")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs")


# recurse into dependencies that aren't built elsewhere



# And others (typically CMSIS implementations) need to export non-system header
# files. Please don't use this facility. Please. It's much, much better to fix
# implementations that import these headers to import them using the full path.
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/PAL-Impl/Services-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/Port/Platform-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config/Linux")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/mbed-client-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib/mbed-client-randlib")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/nanostack-event-loop")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include")


# modules with custom CMake build systems may append to the
# MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS property to add compile-time-determined include
# directories:
get_property(GLOBAL_INCLUDE_DIRS GLOBAL PROPERTY MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS)
include_directories(${GLOBAL_INCLUDE_DIRS})

# Provide versions of all the components we depend on, the corresponding
# preprocessor definitions are generated in mbed_edge_config.h
set(MBED_EDGE_BUILD_NS_HAL_PAL_VERSION_STRING "0.0.0")
set(MBED_EDGE_BUILD_NS_HAL_PAL_VERSION_MAJOR 0)
set(MBED_EDGE_BUILD_NS_HAL_PAL_VERSION_MINOR 0)
set(MBED_EDGE_BUILD_NS_HAL_PAL_VERSION_PATCH 0)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME ns-hal-pal)

# recurse into subdirectories for this component, using the two-argument
# add_subdirectory because the directories referred to here exist in the source
# tree, not the working directory
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/ns-hal-pal/ns-hal-pal"
    "${CMAKE_BINARY_DIR}/mbed-edge-modules/ns-hal-pal/ns-hal-pal"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(ns-hal-pal PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=ns-hal-pal")

# include .cmake files provided by the target:
