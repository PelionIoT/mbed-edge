

cmake_minimum_required(VERSION 2.8.11)

include_directories("${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib/source")


set(MBED_EDGE_BUILD_AUTO_NANOSTACK-RANDLIB_C_FILES
    "${CMAKE_SOURCE_DIR}/../../mbed-edge-module-sources/nanostack-randlib/source/randLIB.c"
)
# force dependency on the config header for c files, which CMake otherwise wouldn't track:
set_property(SOURCE ${MBED_EDGE_BUILD_AUTO_NANOSTACK-RANDLIB_C_FILES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")


add_library(nanostack-randlib
    ${MBED_EDGE_BUILD_AUTO_NANOSTACK-RANDLIB_C_FILES}
)

edge_postprocess_target(LIBRARY nanostack-randlib)



target_link_libraries(nanostack-randlib
    
)

