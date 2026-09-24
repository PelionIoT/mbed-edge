# Native Windows target. Select the x64 compiler using the generator (-A x64
# for Visual Studio), or an x64 developer shell when using Ninja.
if (NOT CMAKE_HOST_WIN32)
    message(FATAL_ERROR "This toolchain requires a native Windows build host.")
endif ()
# Leave CMAKE_SYSTEM_NAME to CMake's host detection. Setting it explicitly
# would classify this native build as cross compilation and disable try_run.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
