file (GLOB SOURCES ./*.cpp ./*.c ${ROOT_HOME}/common/integer_length.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (edge-client-mock-lib ${SOURCES})
include_directories (../cpputest-custom-types)
target_include_directories (edge-client-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-client-mock-lib PUBLIC ${ROOT_HOME}/test/test-lib)
