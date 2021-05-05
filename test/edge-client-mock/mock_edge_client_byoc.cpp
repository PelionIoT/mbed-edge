#include <stdint.h>
#include "CppUTestExt/MockSupport.h"

extern "C" {
#include "edge-client/edge_client_byoc.h"

byoc_data_t *edgeclient_create_byoc_data(char *cbor_file)
{
    return (byoc_data_t*) mock().actualCall("edgeclient_create_byoc_data")
        .withPointerParameter("cbor_file", cbor_file)
        .returnPointerValue();
}

int edgeclient_inject_byoc(byoc_data_t *byoc_data)
{
    return mock().actualCall("edgeclient_inject_byoc").withPointerParameter("byoc_data", byoc_data).returnIntValue();
}

}
