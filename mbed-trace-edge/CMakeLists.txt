# This is needed because mbedTrace in mbed-cloud-client doesn't depend on nanostack.
# And that's because nanostack does not use CMake.

file (GLOB SOURCES ../lib/mbed-cloud-client/mbed-trace/source/*.c)
add_library(mbedTraceEdge ${SOURCES})

target_link_libraries(mbedTraceEdge nanostack)
