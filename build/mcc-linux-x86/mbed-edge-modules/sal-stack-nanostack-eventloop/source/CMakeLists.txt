

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source")


set(MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_CPP_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/system_timer.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/ns_timeout.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/minar_hal_timer.cpp"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/event.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/ns_timer.c"
)
# force dependency on the config header for cpp files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_CPP_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/timer_sys.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/ns_timer.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/event.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/system_timer.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/ns_timeout.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/event.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/sal-stack-nanostack-eventloop/source/ns_timer.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(sal-stack-nanostack-eventloop
    ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_CPP_FILES}
    ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_SAL-STACK-NANOSTACK-EVENTLOOP_C_FILES}
)

edge_postprocess_target(LIBRARY sal-stack-nanostack-eventloop)



target_link_libraries(sal-stack-nanostack-eventloop
    nanostack-libservice
)

