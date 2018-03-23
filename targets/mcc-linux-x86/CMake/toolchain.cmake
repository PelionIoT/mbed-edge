cmake_minimum_required(VERSION 2.8)

# default to GNU99
set(CMAKE_C_FLAGS "$ENV{MCC_LINUX_X86_EXTRA_C_FLAGS} -std=gnu99" CACHE STRING "" FORCE)
# PAL target name
set(PAL_TARGET_DEVICE "TARGET_x86_x64")
# add extra args if found in the environment
set(CMAKE_CXX_FLAGS "$ENV{MCC_LINUX_X86_EXTRA_CXX_FLAGS}" CACHE STRING "" FORCE)
# ugly hack for fixing link issues
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} $ENV{MCC_LINUX_X86_EXTRA_LD_FLAGS} -Wl,--start-group" CACHE STRING "" FORCE)
# import definitions from environment
add_definitions($ENV{MCC_LINUX_X86_EXTRA_DEFS})
link_libraries($ENV{MCC_LINUX_X86_EXTRA_LIBS} rt pthread)
# Mark to detect yotta targets
set(MBED_EDGE_BUILD_TARGET 1)

# check that we are actually running on Linux, if we're not then we may pull in
# incorrect dependencies.
if(NOT (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux"))
    message(FATAL_ERROR "This Linux native target will not work on non-Linux platforms (your platform is ${CMAKE_HOST_SYSTEM_NAME}).")
endif()

