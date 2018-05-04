

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns-hal-pal")


set(MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_CPP_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_hal_init.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_event_loop.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_interrupt.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_random.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_timer.cpp"
)
# force dependency on the config header for cpp files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_CPP_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_HEADER_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_event_loop.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_interrupt_private.h"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_hal_init.h"
)
# force dependency on the config header for header files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_HEADER_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
set(MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_hal_init.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/ns_event_loop.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_interrupt.c"
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/ns-hal-pal/arm_hal_random.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(ns-hal-pal
    ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_CPP_FILES}
    ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_HEADER_FILES}
    ${MBED_EDGE_BUILD_AUTO_NS-HAL-PAL_C_FILES}
)

edge_postprocess_target(LIBRARY ns-hal-pal)



target_link_libraries(ns-hal-pal
    pal
    nanostack-libservice
    nanostack-randlib
    sal-stack-nanostack-eventloop
)

