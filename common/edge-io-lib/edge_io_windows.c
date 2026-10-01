/* SPDX-License-Identifier: Apache-2.0 */
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#include "common/edge_io_lib.h"
#include "common/edge_platform.h"

bool edge_io_file_exists(const char *path)
{
    return _access(path, 0) == 0;
}

bool edge_io_acquire_lock_for_socket(const char *path, int *lock_fd)
{
    char *filename;
    *lock_fd = -1;
    if (asprintf(&filename, "%s.lock", path) < 0) return false;
    errno_t result = _sopen_s(lock_fd, filename, _O_RDWR | _O_CREAT | _O_BINARY,
                            _SH_DENYRW, _S_IREAD | _S_IWRITE);
    free(filename);
    return result == 0;
}

bool edge_io_release_lock_for_socket(const char *path, int lock_fd)
{
    (void)path;
    /* Retain the file: deleting after close could race a new lock owner. */
    return _close(lock_fd) == 0;
}

int edge_io_unlink(const char *path)
{
    return _unlink(path);
}
