cmake_minimum_required(VERSION 2.8)
MESSAGE("Building with Wise3610 toolchain")
SET (HOST_TRIPLET "arm-openwrt-linux")

SET (CMAKE_SYSROOT $ENV{ARMGCC_DIR})

IF(NOT CMAKE_SYSROOT)
    MESSAGE(FATAL_ERROR "***Please set ARMGCC_DIR in envionment variables***")
ENDIF()

SET (TOOLCHAIN_BIN_DIR $ENV{ARMGCC_DIR}/bin)

SET(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_PROCESSOR arm)

SET (CMAKE_C_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-gcc CACHE FILEPATH "" FORCE)
SET (CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-g++)
SET (CMAKE_ASM_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-gcc)

SET (TOOLCHAIN_DIR ${ARMGCC_DIR})

SET (CPATH $ENV{ARM_LIBC_DIR}/usr/include/)
SET (LD_LIBRARY_PATH $ENV{ARM_LIBC_DIR}/usr/lib/)
SET (LIBRARY_PATH $ENV{ARM_LIBC_DIR}/usr/lib/)

# A work-around for CHECK_C_SOURCE_COMPILES TCP_USER_TIMEOUT test in lib/libwebsockets/CMakeLists.txt
# The test succeeds, but real cross-compilation fails, because the value is defined in linux/tcp.h instead
# of netinet/tcp.h
add_definitions(-DTCP_USER_TIMEOUT=18)

# default to GNU99
set(CMAKE_C_FLAGS "-fpic -Wall -std=gnu99 -pthread" CACHE STRING "" FORCE)

# import definitions from environment
add_definitions(-D_GNU_SOURCE)
SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lm")

# check that we are actually running on Linux, if we're not then we may pull in
# incorrect dependencies.
if(NOT (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux"))
    message(FATAL_ERROR "This Linux native target will not work on non-Linux platforms")
endif()

