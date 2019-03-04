cmake_minimum_required(VERSION 3.5)
MESSAGE("Building with mcc-linux-x86 toolchain")

# default to GNU99
set (CMAKE_C_FLAGS "-fpic -Wall -std=gnu99 -pthread" CACHE STRING "" FORCE)
set (CMAKE_CXX_FLAGS "-Wall -Wno-c++14-compat" CACHE STRING "" FORCE)

# check that we are actually running on Linux, if we're not then we may pull in
# incorrect dependencies.
if(NOT (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux"))
    message(FATAL_ERROR "This Linux native target will not work on non-Linux platforms (your platform is ${CMAKE_HOST_SYSTEM_NAME}).")
endif()

