file (GLOB SOURCES ./*.cpp ../../common/edge_trace.c)

enable_language(C)
enable_language(CXX)

set (TEST_DATA_DIR ${ROOT_HOME}/test/pt-client-2/data)
add_definitions(-DTEST_DATA_DIR="${TEST_DATA_DIR}")

add_executable (pt-client-2-test ${SOURCES})

include_directories (../cpputest-custom-types ../libwebsocket-mock)
target_include_directories (pt-client-2-test PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (pt-client-2-test PUBLIC ${ROOT_HOME}/test/test-lib)

target_link_libraries (pt-client-2-test nanostacklibservice edge-mutex-mock pt-client-2
  edge-apr-base64 edge-default-message-id-generator pt-api-error-codes
  edge-websocket-common-mock edge-msg-api-common-mock edge-mutex-helper
  libwebsocket-mock-minimal-lib libevent-mock-lib CppUTest CppUTestExt pthread mbedTrace)
