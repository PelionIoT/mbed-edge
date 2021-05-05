file (GLOB SOURCES ./*.cpp ./*.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (kcm-mock-lib ${SOURCES})

target_include_directories (kcm-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
