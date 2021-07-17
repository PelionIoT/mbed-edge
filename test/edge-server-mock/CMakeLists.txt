file (GLOB SOURCES ./*.cpp ./*.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
if(FOTA_ENABLE)
    add_definitions(-DMBED_EDGE_SUBDEVICE_FOTA)
endif()
add_library (edge-server-mock-lib ${SOURCES})

target_include_directories (edge-server-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-server-mock-lib PUBLIC ${ROOT_HOME}/test/test-lib)
