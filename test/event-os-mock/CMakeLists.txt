file (GLOB SOURCES ./*.cpp ./*.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (event-os-mock-lib ${SOURCES})

target_include_directories (event-os-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
