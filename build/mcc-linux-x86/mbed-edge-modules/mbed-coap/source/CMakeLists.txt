

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source")


set(MBED_EDGE_BUILD_AUTO_MBED-COAP_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/include/sn_coap_protocol_internal.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/mbed-coap/sn_config.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/include/sn_coap_header_internal.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/mbed-coap/sn_coap_header.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/mbed-coap/sn_coap_protocol.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-COAP_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_MBED-COAP_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/sn_coap_header_check.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/sn_coap_builder.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/sn_coap_protocol.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-coap/source/sn_coap_parser.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-COAP_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(mbed-coap
    ${MBED_EDGE_BUILD_AUTO_MBED-COAP_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_MBED-COAP_C_FILES}
)

edge_postprocess_target(LIBRARY mbed-coap)



target_link_libraries(mbed-coap
    nanostack-libservice
    mbed-trace
    nanostack-randlib
)

