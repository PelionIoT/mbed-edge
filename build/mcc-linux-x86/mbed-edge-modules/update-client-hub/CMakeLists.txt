


project(update-client-hub)


# include root directories of all components we depend on (directly and
# indirectly, including ourself)
include_directories("${CMAKE_SOURCE_DIR}/../..")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbedtls")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-trace")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop")


# recurse into dependencies that aren't built elsewhere



# And others (typically CMSIS implementations) need to export non-system header
# files. Please don't use this facility. Please. It's much, much better to fix
# implementations that import these headers to import them using the full path.
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/common")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/control-center")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/manifest-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/atomic-queue")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/paal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/lwm2m-mbed")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-linux")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/firmware-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-http-socket")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/device-identity")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/monitor")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-filesystem")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-http")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-flashiap")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-blockdevice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-target-specific")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/PAL-Impl/Services-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Source/Port/Platform-API")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/pal/Configs/pal_config/Linux")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/secsrv-cbor")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/factory-configurator-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/factory-configurator-client/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/fcc-bundle-handler")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-bundle-handler/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/key-config-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/utils/utils")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/logger/logger")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/storage/storage")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto/crypto")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/crypto-service")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/crypto-service/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-base/ftcd-comm-base")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/ftcd-comm-socket/ftcd-comm-socket")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/key-config-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client-esfs/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-cloud-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-mbed-tls")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-classic")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/nsdl-c")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-cloud-client/mbed-client/mbed-client-c/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/mbed-client-libservice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/common")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/control-center")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/manifest-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/atomic-queue")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/paal")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/lwm2m-mbed")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-linux")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/firmware-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-http-socket")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/device-identity")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/monitor")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-filesystem")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-manager")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/source-http")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-flashiap")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-blockdevice")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/update-client-hub/modules/pal-target-specific")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/mbed-coap")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/include")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib/mbed-client-randlib")
include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/nanostack-event-loop")


# modules with custom CMake build systems may append to the
# MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS property to add compile-time-determined include
# directories:
get_property(GLOBAL_INCLUDE_DIRS GLOBAL PROPERTY MBED_EDGE_BUILD_GLOBAL_INCLUDE_DIRS)
include_directories(${GLOBAL_INCLUDE_DIRS})

# Provide versions of all the components we depend on, the corresponding
# preprocessor definitions are generated in mbed_edge_config.h
set(MBED_EDGE_BUILD_UPDATE_CLIENT_HUB_VERSION_STRING "0.0.0")
set(MBED_EDGE_BUILD_UPDATE_CLIENT_HUB_VERSION_MAJOR 0)
set(MBED_EDGE_BUILD_UPDATE_CLIENT_HUB_VERSION_MINOR 0)
set(MBED_EDGE_BUILD_UPDATE_CLIENT_HUB_VERSION_PATCH 0)

# provide the name of the current module so that it's available to custom CMake
# even if custom CMake does weird things with project()
set(MBED_EDGE_BUILD_MODULE_NAME update-client-hub)

# recurse into subdirectories for this component, using the two-argument
# add_subdirectory because the directories referred to here exist in the source
# tree, not the working directory
add_subdirectory(
    "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed-edge-modules/update-client-hub/update-client-hub"
    "${CMAKE_BINARY_DIR}/mbed-edge-modules/update-client-hub/update-client-hub"
)

# make MBED_EDGE_BUILD_MODULE_NAME available as a preprocessor symbol when
# compiling this module:
target_compile_definitions(update-client-hub PRIVATE "-DMBED_EDGE_BUILD_MODULE_NAME=update-client-hub")

# include .cmake files provided by the target:
