#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

extern "C" {

int mocked_access(const char *__name, int __type)
{
    return mock()
            .actualCall("access")
            .withStringParameter("path", __name)
            .withIntParameter("type", __type)
            .returnIntValue();
}

int mocked_open(const char *__file, int __oflagv, mode_t mode)
{
    return mock()
            .actualCall("open")
            .withStringParameter("path", __file)
            .withIntParameter("flag", __oflagv)
            .withIntParameter("mode", mode)
            .returnIntValue();
}

int mocked_unlink(const char *path)
{
    return mock().actualCall("unlink").withStringParameter("path", path).returnIntValue();
}

int mocked_flock(int __fd, int __operation)
{
    return mock()
            .actualCall("flock")
            .withIntParameter("fd", __fd)
            .withIntParameter("operation", __operation)
            .returnIntValue();
}

}
