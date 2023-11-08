file (GLOB SOURCES ./*.cpp ${ROOT_HOME}/common/edge-io-lib/edge_io_lib.c)
enable_language(C)
enable_language(CXX)


add_executable (edge-io-lib-test ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (edge-io-lib-test PUBLIC ${CPPUTEST_HOME}/include)

target_link_libraries (edge-io-lib-test nanostacklibservice mbedTrace CppUTest CppUTestExt)

