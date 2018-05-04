

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source")


set(MBED_EDGE_BUILD_AUTO_NANOSTACK-LIBSERVICE_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/IPv6_fcf_lib/ip_fsc.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/libList/ns_list.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/libip6string/stoip6.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/libip6string/ip6tos.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/libBits/common_functions.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/nvmHelper/ns_nvm_helper.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/nsdynmemLIB/nsdynmemLIB.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-libservice/source/libTrace/ns_trace.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_NANOSTACK-LIBSERVICE_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(nanostack-libservice
    ${MBED_EDGE_BUILD_AUTO_NANOSTACK-LIBSERVICE_C_FILES}
)

edge_postprocess_target(LIBRARY nanostack-libservice)



target_link_libraries(nanostack-libservice
    
)

