file (GLOB SOURCES ./*.cpp ${ROOT_HOME}/common/integer_length.c ${ROOT_HOME}/common/pt_api_error_codes.c)
enable_language(C)
enable_language(CXX)

add_executable (edge-rpc-test ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (edge-rpc-test PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-rpc-test PUBLIC ${ROOT_HOME}/lib/jsonrpc)
target_include_directories (edge-rpc-test PUBLIC ${ROOT_HOME}/test/test-lib)

target_link_libraries (edge-rpc-test test-lib libevent-mock-lib rpc jansson jsonrpc mbedTrace nanostacklibservice CppUTest CppUTestExt)
