

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source")


set(MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include/sotp.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_log.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_int.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include/esfs.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include/esfs_performance.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_shared_lock.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/include/esfs_file_name.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_shared_lock.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/esfs.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/esfs_file_name.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_no_sotp.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/esfs_performance.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/mbed-client-esfs/source/sotp/sotp_log.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(mbed-client-esfs
    ${MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_MBED-CLIENT-ESFS_C_FILES}
)

edge_postprocess_target(LIBRARY mbed-client-esfs)



target_link_libraries(mbed-client-esfs
    pal
    mbed-trace
)

