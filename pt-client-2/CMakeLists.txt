if (ENABLE_UC_HUB)
file (GLOB SOURCES ./*.c ../edge-rpc/rpc_timeout_api.c ../lib/mbed-cloud-client/update-client-hub/modules/manifest-manager/source/*.c)
else()
file (GLOB SOURCES ./*.c ../edge-rpc/rpc_timeout_api.c)
endif()

if (TARGET_GROUP STREQUAL test)
  add_definitions(-DBUILD_TYPE_TEST)
endif ()

include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

add_library (pt-client-2 ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
add_definitions ("-D CLIENT_TIMEOUT_CHECK_INTERVAL_MS=${EDGE_CLIENT_TIMEOUT_CHECK_INTERVAL_MS}")
add_definitions ("-D CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS=${EDGE_CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS}")

target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/jsonrpc)
target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../edge-rpc)

if (ENABLE_UC_HUB)

  add_definitions(-DARM_UC_PROFILE_MBED_CLOUD_CLIENT=1)
  add_definitions(-D__LINUX__=1)
  add_definitions(-DSN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE=1024)

  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/manifest-manager/source)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/common)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/common/update-client-common)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/manifest-manager)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/atomic-queue)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/metadata-header)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/control-center)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/update-client-hub/modules/device-identity)

  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/mbed-client-pal/Source)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/mbed-client-pal/Source/PAL-Impl/Services-API)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/mbed-client-pal/Configs/pal_config)
  target_include_directories (pt-client-2 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/mbed-cloud-client/mbed-client-pal/Configs/pal_config/Linux)

endif()

SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -shared")

if (TARGET_GROUP STREQUAL test)
  target_link_libraries (pt-client-2 jansson rpc nanostacklibservice mbedTrace)
else ()
  target_link_libraries (pt-client-2 edge-websocket-common
    edge-integer-length edge-apr-base64 edge-default-message-id-generator
    pt-api-error-codes edge-msg-api event jansson websockets rpc nanostacklibservice mbedTrace)
endif()
