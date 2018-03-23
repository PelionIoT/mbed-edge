

if(MBED_EDGE_BUILD_META_TOOLCHAIN_FILE_INCLUDED)
    return()
endif()
set(MBED_EDGE_BUILD_META_TOOLCHAIN_FILE_INCLUDED 1)

if(${CMAKE_SOURCE_DIR} MATCHES CMakeTmp) 
  include("${CMAKE_SOURCE_DIR}/../../../../targets/mcc-linux-x86/CMake/toolchain.cmake") 
else() 
  include("${CMAKE_SOURCE_DIR}/../../targets/mcc-linux-x86/CMake/toolchain.cmake") 
endif()
