# Edge include hierarchy
include_directories (common)
include_directories (config)
include_directories (edge-client)
include_directories (edge-core)
include_directories (edge-rpc)
include_directories (include)
include_directories (lib/jsonrpc)

# Jansson include, include generated headers too
include_directories (lib/jansson/jansson/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/lib/jansson/jansson/include)

# Libevent include, include generated headers too
include_directories (lib/libevent/libevent/include)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/lib/libevent/libevent/include)

# Libwebsockets include
include_directories (lib/libwebsockets/libwebsockets/lib)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/lib/libwebsockets/libwebsockets)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/lib/libwebsockets/libwebsockets/include)

# mbedtls
include_directories (lib/mbedtls/include)
include_directories (lib/mbedtls/include/mbedtls/)
SET (MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES "${ROOT_HOME}/lib/mbed-cloud-client")

# cloud client
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES})
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/source)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-cloud-client)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-edge-cloud-client-dependency-sources-internal/source)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client/mbed-client)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client/source)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client/source/include)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client/mbed-client-c)

# update client
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/update-client-hub/)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/update-client-hub/modules/common/)

# CoAP lib
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-coap/mbed-coap)

# HAL-PAL
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/ns-hal-pal)

# nanostack library
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/nanostack-libservice/)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/nanostack-libservice/mbed-client-libservice)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/sal-stack-nanostack-eventloop/nanostack-event-loop)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/sal-stack-nanostack-eventloop)

# mbed-trace for logging
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-trace)

# factory configuration headers
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/factory-configurator-client/factory-configurator-client/factory-configurator-client)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/factory-configurator-client/fcc-bundle-handler/fcc-bundle-handler)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/factory-configurator-client/fcc-output-info-handler/fcc-output-info-handler)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/factory-configurator-client/key-config-manager/key-config-manager)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/factory-configurator-client/key-config-manager)

# certificate enrollment client headers:
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/certificate-enrollment-client)

# pal headers
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client-pal/Source)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client-pal/Source/PAL-Impl/Services-API)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client-pal/Configs/pal_config)
include_directories (${MBED_CLOUD_CLIENT_DEPENDENCY_SOURCES}/mbed-client-pal/Configs/pal_config/Linux)
