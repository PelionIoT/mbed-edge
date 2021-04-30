file (GLOB SOURCES ./*.cpp ${ROOT_HOME}/edge-rpc/rpc_timeout_api.c ${ROOT_HOME}/edge-client/edge_client_format_values.c ${ROOT_HOME}/lib/mbedtls/crypto/library/base64.c ../test-lib/msg_api_test_helper.cpp)
enable_language(C)
enable_language(CXX)

set (TEST_DATA_DIR ${ROOT_HOME}/test/edge-core/data)

add_executable (edge-core-test ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

include_directories (../cpputest-custom-types ../libwebsocket-mock ../event-os-mock)
target_include_directories (edge-core-test PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-core-test PUBLIC ${ROOT_HOME}/test/test-lib)

target_link_libraries (edge-core-test edge-msg-api edge-websocket-common
  test-lib libwebsocket-mock-lib libevent-mock-lib pal-mock-lib edge-client-mock-lib edge-core
  event-os-mock-lib kcm-mock-lib CppUTest CppUTestExt)

add_definitions(-DTEST_DATA_DIR="${TEST_DATA_DIR}")

