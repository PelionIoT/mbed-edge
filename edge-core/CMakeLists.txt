file (GLOB SOURCES ./*.c ../common/*.c)

if (TARGET_GROUP STREQUAL test)
  add_library (edge-core ${SOURCES})
  add_definitions(-DBUILD_TYPE_TEST)
else ()
  list(APPEND SOURCES ../common/edge-mutex/edge_mutex.c)
  list(APPEND SOURCES ../common/edge-io-lib/edge_io_lib.c)
  add_executable (edge-core ${SOURCES})
endif ()

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
add_definitions ("-D SERVER_TIMEOUT_CHECK_INTERVAL_MS=${EDGE_SERVER_TIMEOUT_CHECK_INTERVAL_MS}")
add_definitions ("-D SERVER_REQUEST_TIMEOUT_THRESHOLD_MS=${EDGE_SERVER_REQUEST_TIMEOUT_THRESHOLD_MS}")

target_include_directories (edge-core PUBLIC ${CMAKE_CURRENT_LIST_DIR})
if (TARGET_GROUP STREQUAL test)
  target_link_libraries (edge-core jansson jsonrpc libevent-mock-lib rpc mbedTrace libservice edge-client-mock-lib pal-mock-lib test-lib pthread)
else ()
  target_link_libraries (edge-core jansson websockets event rpc edge-client)
endif ()

