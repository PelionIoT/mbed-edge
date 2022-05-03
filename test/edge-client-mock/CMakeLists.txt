file (GLOB SOURCES ./*.cpp ./*.c ${ROOT_HOME}/common/integer_length.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
if(FOTA_ENABLE)
    add_definitions(-DMBED_EDGE_SUBDEVICE_FOTA)
endif()

if(NOT EXISTS ${ROOT_HOME}/lib/pal-platform/Middleware/curl/curl/include)
    message(FATAL_ERROR "curl not found in lib/pal-platform/Middleware/curl/curl/include")
endif()

include_directories (${ROOT_HOME}/lib/pal-platform/Middleware/curl/curl/include)
add_library (edge-client-mock-lib ${SOURCES})
include_directories (../cpputest-custom-types)
target_include_directories (edge-client-mock-lib PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-client-mock-lib PUBLIC ${ROOT_HOME}/test/test-lib)
