#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <fcntl.h>
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

extern "C"
{
#include "common/edge_io_lib.h"
}


TEST_GROUP(edge_io_lib) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edge_io_lib, test_edge_io_file_exists_exists)
{
    mock().expectOneCall("access")
            .withStringParameter("path", "/tmp/foo")
            .withIntParameter("type", F_OK)
            .andReturnValue(0);
    bool found = edge_io_file_exists("/tmp/foo");
    CHECK(true == found);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_edge_io_file_exists_exists_not)
{
    mock().expectOneCall("access")
            .withStringParameter("path", "/tmp/foo")
            .withIntParameter("type", F_OK)
            .andReturnValue(-1);
    bool found = edge_io_file_exists("/tmp/foo");
    CHECK(false == found);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_acquire_lock_for_socket_cannot_create)
{
    mock().expectOneCall("open")
            .withStringParameter("path", "/tmp/foo.lock")
            .withIntParameter("flag", O_CREAT | O_RDONLY)
            .withIntParameter("mode", 0600)
            .andReturnValue(-1);
    int lock_fd = 100;
    bool success = edge_io_acquire_lock_for_socket("/tmp/foo", &lock_fd);
    CHECK(false == success);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_acquire_lock_for_socket_cannot_acquire)
{
    mock().expectOneCall("open")
            .withStringParameter("path", "/tmp/foo.lock")
            .withIntParameter("flag", O_CREAT | O_RDONLY)
            .withIntParameter("mode", 0600)
            .andReturnValue(1000);
    int lock_fd = 100;
    mock().expectOneCall("flock")
            .withIntParameter("fd", 1000)
            .withIntParameter("operation", LOCK_EX | LOCK_NB)
            .andReturnValue(-1);
    bool success = edge_io_acquire_lock_for_socket("/tmp/foo", &lock_fd);
    CHECK(false == success);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_acquire_lock_for_socket_success)
{
    mock().expectOneCall("open")
            .withStringParameter("path", "/tmp/foo.lock")
            .withIntParameter("flag", O_CREAT | O_RDONLY)
            .withIntParameter("mode", 0600)
            .andReturnValue(1000);
    int lock_fd = 100;
    mock().expectOneCall("flock")
            .withIntParameter("fd", 1000)
            .withIntParameter("operation", LOCK_EX | LOCK_NB)
            .andReturnValue(0);
    bool success = edge_io_acquire_lock_for_socket("/tmp/foo", &lock_fd);
    CHECK(true == success);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_release_lock_for_socket_flock_fails)
{
    mock().expectOneCall("flock")
            .withIntParameter("fd", 1000)
            .withIntParameter("operation", LOCK_UN | LOCK_NB)
            .andReturnValue(-1);
    mock().expectOneCall("unlink").withStringParameter("path", "/tmp/foo.lock").andReturnValue(0);
    edge_io_release_lock_for_socket("/tmp/foo", 1000);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_release_lock_for_socket_unlink_fails)
{
    mock().expectOneCall("flock")
            .withIntParameter("fd", 1000)
            .withIntParameter("operation", LOCK_UN | LOCK_NB)
            .andReturnValue(0);
    mock().expectOneCall("unlink").withStringParameter("path", "/tmp/foo.lock").andReturnValue(-1);
    edge_io_release_lock_for_socket("/tmp/foo", 1000);
    mock().checkExpectations();
}

TEST(edge_io_lib, test_release_lock_for_socket_success)
{
    mock().expectOneCall("flock")
            .withIntParameter("fd", 1000)
            .withIntParameter("operation", LOCK_UN | LOCK_NB)
            .andReturnValue(0);
    mock().expectOneCall("unlink").withStringParameter("path", "/tmp/foo.lock").andReturnValue(0);
    edge_io_release_lock_for_socket("/tmp/foo", 1000);
    mock().checkExpectations();
}
