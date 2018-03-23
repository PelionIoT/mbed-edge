


project(pal)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbedtls")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-trace")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal")


# recurse into dependencies that aren't built elsewhere
add_subdirectory(
   "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/mbedtls"
   "${CMAKE_BINARY_DIR}/mbed-edge-modules/mbedtls"
)



# And others (typically CMSIS implementations) need to export non-system header
# files. Please don't use this facility. Please. It's much, much better to fix
# implementations that import these headers to import them using the full path.
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/PAL-Impl/Services-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/Port/Platform-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config/Linux")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/mbed-client-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/PAL-Impl/Services-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/Port/Platform-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config/Linux")


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
set(MBED_EDGE_BUILD_PAL_VERSION_STRING "1.0.0")
set(MBED_EDGE_BUILD_PAL_VERSION_MAJOR 1)
set(MBED_EDGE_BUILD_PAL_VERSION_MINOR 0)
set(MBED_EDGE_BUILD_PAL_VERSION_PATCH 0)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME pal)

# delegate to an existing CMakeLists.txt:
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal"
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/pal/existing"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(pal PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=pal")

# include .cmake files provided by the target:
