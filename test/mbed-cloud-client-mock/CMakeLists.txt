set(MBED_CLOUD_CLIENT ${ROOT_HOME}/lib/mbed-cloud-client)

enable_language(C)
enable_language(CXX)

file (GLOB SOURCES *.cpp *.c)

set(MBED_CLOUD_CLIENT ${ROOT_HOME}/lib/mbed-cloud-client)
set(CLIENT_SOURCE_LOC  ${MBED_CLOUD_CLIENT}/mbed-client/source/)
file(GLOB M2M_SOURCES ${ROOT_HOME}/test/test-lib/m2mcallbackstorage.cpp)

add_library (mbed-cloud-client-mock ${SOURCES} ${M2M_SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
include_directories (../cpputest-custom-types)

target_include_directories (mbed-cloud-client-mock PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (mbed-cloud-client-mock PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (mbed-cloud-client-mock PUBLIC ${ROOT_HOME}/test/test-lib/)
target_include_directories (mbed-cloud-client-mock PUBLIC ${MBED_CLOUD_CLIENT}/mbed-client/source/include)

if (ENABLE_SUBDEVICE_FOTA)
target_include_directories (mbed-cloud-client-mock PUBLIC ${MBED_CLOUD_CLIENT}/update-client-hub/modules/common/update-client-common)
endif()
