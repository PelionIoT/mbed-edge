#define TRACE_GROUP "edge_io"
#include "CppUTestExt/MockSupport.h"

#ifdef __cplusplus
extern "C" {
#include "common/edge_io_lib.h"
#endif

bool edge_io_file_exists(const char *path)
{
    return mock().actualCall("edge_io_file_exists").withStringParameter("path", path).returnBoolValue();
}

bool edge_io_acquire_lock_for_socket(const char *path, int *lock_fd)
{
    return mock()
            .actualCall("edge_io_acquire_lock_for_socket")
            .withStringParameter("path", path)
            .withOutputParameter("lock_fd", lock_fd)
            .returnBoolValue();
}

bool edge_io_release_lock_for_socket(const char *path, int lock_fd)
{
    return mock().actualCall("edge_io_release_lock_for_socket")
            .withStringParameter("path", path)
            .withIntParameter("lock_fd", lock_fd)
            .returnBoolValue();
}

int edge_io_unlink(const char *path)
{
    return mock().actualCall("edge_io_unlink").withStringParameter("path", path).returnIntValue();
}

#ifdef __cplusplus
}
#endif
