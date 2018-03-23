


project(nanostack-randlib)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib")


# recurse into dependencies that aren't built elsewhere



# And others (typically CMSIS implementations) need to export non-system header
# files. Please don't use this facility. Please. It's much, much better to fix
# implementations that import these headers to import them using the full path.
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib/mbed-client-randlib")


# modules with custom CMake build systems may append to the
# MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS property to add compile-time-determined include
# directories:
get_property(GLOBAL_INCLUDE_DIRS GLOBAL PROPERTY MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS)
include_directories(${GLOBAL_INCLUDE_DIRS})

# Provide versions of all the components we depend on, the corresponding
# preprocessor definitions are generated in mbed_edge_config.h
set(MBED_EDGE_BUILD_NANOSTACK_RANDLIB_VERSION_STRING "1.2.0")
set(MBED_EDGE_BUILD_NANOSTACK_RANDLIB_VERSION_MAJOR 1)
set(MBED_EDGE_BUILD_NANOSTACK_RANDLIB_VERSION_MINOR 2)
set(MBED_EDGE_BUILD_NANOSTACK_RANDLIB_VERSION_PATCH 0)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME nanostack-randlib)

# recurse into subdirectories for this component, using the two-argument
# add_subdirectory because the directories referred to here exist in the source
# tree, not the working directory
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/nanostack-randlib/source"
    "${CMAKE_BINARY_DIR}/mbed-edge-modules/nanostack-randlib/source"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(nanostack-randlib PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=nanostack-randlib")

# include .cmake files provided by the target:
