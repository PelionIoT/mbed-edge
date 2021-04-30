file (GLOB SOURCES ./*.cpp ./*.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (pal-mock-lib ${SOURCES})

target_include_directories (pal-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
