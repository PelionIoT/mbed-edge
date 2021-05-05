
#define TRACE_GROUP "rf"
#include "CppUTestExt/MockSupport.h"

#ifdef __cplusplus
extern "C" {
#include "common/read_file.h"
#endif

int edge_read_file(const char* filename, uint8_t** data, size_t *read) {
    return mock().actualCall("edge_read_file").returnIntValue();
}

#ifdef __cplusplus
}
#endif
