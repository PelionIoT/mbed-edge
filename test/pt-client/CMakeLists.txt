file (GLOB SOURCES ./*.cpp ../../common/edge_trace.c)

enable_language(C)
enable_language(CXX)

set (TEST_DATA_DIR ${ROOT_HOME}/test/pt-client/data)
add_definitions(-DTEST_DATA_DIR="${TEST_DATA_DIR}")

add_executable (pt-client-test ${SOURCES})

include_directories (../cpputest-custom-types ../libwebsocket-mock)
target_include_directories (pt-client-test PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (pt-client-test PUBLIC ${ROOT_HOME}/test/test-lib)

target_link_libraries (pt-client-test nanostacklibservice mbedTrace pt-client libwebsocket-mock-lib libevent-mock-lib test-lib CppUTest CppUTestExt pthread)
