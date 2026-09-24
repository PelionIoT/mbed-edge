message(STATUS "Building native Windows x64 target")

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The Windows target requires an x64 compiler. Use -A x64 with Visual Studio.")
endif ()

if (FIRMWARE_UPDATE OR FOTA_ENABLE OR PARSEC_TPM_SE_SUPPORT OR FACTORY_MODE OR RFS_GPIO)
    message(FATAL_ERROR "The Windows build experiment does not yet support firmware updates, FACTORY_MODE, Parsec or GPIO. Configure with -DBYOC_MODE=ON -DFIRMWARE_UPDATE=OFF.")
endif ()

set(OS_BRAND Windows)
set(MBED_CLOUD_CLIENT_DEVICE x86_x64)
set(PAL_TARGET_DEVICE x86_x64)
set(PAL_USE_PLATFORM_FILESYSTEM 1)
set(INCLUDE_FILE_NAME "${CMAKE_BINARY_DIR}/windows-include-flags.txt")
file(WRITE "${INCLUDE_FILE_NAME}" "")

# Use the cloud client's PAL interfaces for the Windows port. Keep credentials
# separate from the executable; the service/installer will supply an absolute
# mount path when service packaging is added.
if (NOT DEFINED PAL_FS_MOUNT_POINT_PRIMARY)
    set(PAL_FS_MOUNT_POINT_PRIMARY "\"./mcc_config\"")
endif ()
if (NOT DEFINED PAL_FS_MOUNT_POINT_SECONDARY)
    set(PAL_FS_MOUNT_POINT_SECONDARY "${PAL_FS_MOUNT_POINT_PRIMARY}")
endif ()
set(PAL_USER_DEFINED_CONFIGURATION "\"${CMAKE_CURRENT_SOURCE_DIR}/config/sotp_fs_windows.h\"")
add_definitions(-DPAL_PLATFORM_DEFINED_CONFIGURATION="${CMAKE_CURRENT_SOURCE_DIR}/config/pal_windows.h")

add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00
                -D_CRT_SECURE_NO_WARNINGS -DTARGET_IS_PC_WINDOWS)
