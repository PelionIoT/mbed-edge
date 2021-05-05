#include "pal.h"
#include "pal_fileSystem.h"
#include "CppUTestExt/MockSupport.h"

palStatus_t pal_fsMkDir(const char *pathName)
{
    return (palStatus_t)mock().actualCall("pal_fsMkDir")
            .withStringParameter("pathName", pathName)
            .returnIntValue();
}

palStatus_t pal_fsSetMountPoint(pal_fsStorageID_t dataID, const char *Path)
{
    return (palStatus_t) mock()
            .actualCall("pal_fsSetMountPoint")
            .withIntParameter("dataID", dataID)
            .withStringParameter("Path", Path)
            .returnIntValue();
}

palStatus_t pal_osMutexCreate(palMutexID_t* mutexID)
{
    return (palStatus_t)mock().actualCall("pal_osMutexCreate")
                .withPointerParameter("mutexID", (void *)mutexID)
                .returnIntValue();
}

palStatus_t pal_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    return (palStatus_t)mock().actualCall("pal_osMutexWait")
                .withUnsignedLongIntParameter("mutexID", mutexID)
                .withUnsignedIntParameter("millisec", millisec)
                .returnIntValue();
}

palStatus_t pal_osMutexRelease(palMutexID_t mutexID)
{
    return (palStatus_t)mock().actualCall("pal_osMutexRelease")
                .withUnsignedLongIntParameter("mutexID", mutexID)
                .returnIntValue();
}
