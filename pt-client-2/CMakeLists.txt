file (GLOB SOURCES ./*.c ../edge-rpc/rpc_timeout_api.c)
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
SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -shared")

if (TARGET_GROUP STREQUAL test)
  target_link_libraries (pt-client-2 jansson rpc mbedTraceEdge)
else ()
  target_link_libraries (pt-client-2 edge-websocket-common
    edge-integer-length edge-apr-base64 edge-default-message-id-generator
    pt-api-error-codes edge-msg-api event jansson websockets rpc nanostack mbedTraceEdge)
endif()
