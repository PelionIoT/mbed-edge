

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source")


set(MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/secsrv-cbor/cbor.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/secsrv-cbor/cn-cbor.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-context.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-encoder.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-get.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-cbor.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-create.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/secsrv-cbor/source/cn-error.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(secsrv-cbor
    ${MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_SECSRV-CBOR_C_FILES}
)

edge_postprocess_target(LIBRARY secsrv-cbor)



target_link_libraries(secsrv-cbor
    
)

