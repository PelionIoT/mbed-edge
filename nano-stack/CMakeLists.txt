file (GLOB SOURCES ../lib/mbed-cloud-client/nanostack-libservice/source/libList/*.c)
file (GLOB BIT_SOURCES ../lib/mbed-cloud-client/nanostack-libservice/source/libBits/*.c)
file (GLOB STRING_SOURCES ../lib/mbed-cloud-client/nanostack-libservice/source/libip6string/*.c)

list (APPEND SOURCES ${BIT_SOURCES})
list (APPEND SOURCES ${STRING_SOURCES})

add_library (nanostack STATIC ${SOURCES})
