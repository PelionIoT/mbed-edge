/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "pal.h"
#include "pal_plat_rot.h"
#include "storage_kcm.h"

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "RoT test line %d: %s failed\n", __LINE__, #value); exit(1); } } while (0)
#define OK(value) CHECK((value) == PAL_SUCCESS)

/* Supply the provisioned metadata item; use the real file-based RoT reader
 * and Windows PAL filesystem. This fixture does not replace a KCM test. */
static char path[128];
static bool oversized_path;
palStatus_t storage_rbp_read(const char *name, uint8_t *buffer, size_t size, size_t *actual)
{
    CHECK(strcmp(name, STORAGE_RBP_ROT_FILE_PATH_NAME) == 0);
    *actual = oversized_path ? size : strlen(path);
    CHECK(*actual <= size);
    if (oversized_path) memset(buffer, 'a', size);
    else memcpy(buffer, path, *actual);
    return PAL_SUCCESS;
}

int main(void)
{
    uint8_t expected[PAL_DEVICE_KEY_SIZE_IN_BYTES], result[PAL_DEVICE_KEY_SIZE_IN_BYTES];
    palFileDescriptor_t file;
    size_t actual;
    snprintf(path, sizeof(path), "rot-test-%lu-caf\xc3\xa9.key", GetCurrentProcessId());
    for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = (uint8_t)i;
    OK(pal_fsFopen(path, PAL_FS_FLAG_READWRITEEXCLUSIVE, &file));
    OK(pal_fsFwrite(&file, expected, sizeof(expected), &actual)); CHECK(actual == sizeof(expected));
    OK(pal_fsFclose(&file));
    OK(pal_plat_osGetRoT(result, sizeof(result))); CHECK(memcmp(expected, result, sizeof(result)) == 0);
    CHECK(pal_plat_osGetRoT(NULL, sizeof(result)) == PAL_ERR_INVALID_ARGUMENT);
    CHECK(pal_plat_osGetRoT(result, sizeof(result) - 1) == PAL_ERR_INVALID_ARGUMENT);
    oversized_path = true;
    CHECK(pal_plat_osGetRoT(result, sizeof(result)) == PAL_ERR_BUFFER_TOO_SMALL);
    oversized_path = false;
    OK(pal_fsFopen(path, PAL_FS_FLAG_READWRITETRUNC, &file));
    OK(pal_fsFwrite(&file, expected, sizeof(expected) - 1, &actual));
    OK(pal_fsFclose(&file));
    CHECK(pal_plat_osGetRoT(result, sizeof(result)) == PAL_ERR_GENERIC_FAILURE);
    OK(pal_fsUnlink(path));
    CHECK(pal_plat_osGetRoT(result, sizeof(result)) == PAL_ERR_FS_NO_FILE);
    puts("PASS file-based RoT: UTF-8 paths, exact key length, bounds and missing-file handling");
    return 0;
}
