cmake_minimum_required(VERSION 2.8)

SET (HOST_TRIPLET "arm-openwrt-linux")

SET (CMAKE_SYSROOT $ENV{ARMGCC_DIR})

IF(NOT CMAKE_SYSROOT)
    MESSAGE(FATAL_ERROR "***Please set ARMGCC_DIR in envionment variables***")
ENDIF()

SET (TOOLCHAIN_BIN_DIR $ENV{ARMGCC_DIR}/bin)

SET(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_PROCESSOR arm)

SET (CMAKE_C_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-gcc)
SET (CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-g++)
SET (CMAKE_ASM_COMPILER ${TOOLCHAIN_BIN_DIR}/${HOST_TRIPLET}-gcc)

# default to GNU99
set(CMAKE_C_FLAGS "$ENV{MCC_LINUX_X86_EXTRA_C_FLAGS} -std=gnu99" CACHE STRING "")
# PAL target name
set(PAL_TARGET_DEVICE "TARGET_x86_x64")
# add extra args if found in the environment
set(CMAKE_CXX_FLAGS "$ENV{MCC_LINUX_X86_EXTRA_CXX_FLAGS}" CACHE STRING "")
# ugly hack for fixing link issues
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} $ENV{MCC_LINUX_X86_EXTRA_LD_FLAGS} -Wl,--start-group" CACHE STRING "")
# import definitions from environment
add_definitions($ENV{MCC_LINUX_X86_EXTRA_DEFS})
link_libraries($ENV{MCC_LINUX_X86_EXTRA_LIBS} rt pthread)
set(MBED_EDGE_BUILD_TARGET 1)

# check that we are actually running on Linux, if we're not then we may pull in
# incorrect dependencies.
if(NOT (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux"))
    message(FATAL_ERROR "This Linux native target will not work on non-Linux platforms")
endif()

