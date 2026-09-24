/* Native Windows configuration for the cloud client's existing PAL APIs. */
#ifndef PAL_HEADER_SOTP_FS_WINDOWS
#define PAL_HEADER_SOTP_FS_WINDOWS

#define PAL_USE_HW_ROT 0
#define PAL_USE_HW_RTC 0
#define PAL_USE_HW_TRNG 1
#define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM 1
#define PAL_SIMULATOR_TEST_ENABLE 1
#define PAL_USE_FILESYSTEM 1

#endif
