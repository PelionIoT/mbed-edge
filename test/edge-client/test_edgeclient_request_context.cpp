#include "CppUTest/TestHarness.h"

#include "edge-client/edge_client.h"

TEST_GROUP(edgeclient_request_context) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edgeclient_request_context, test_allocate_request_context_correct_device_uri)
{
    edge_rc_status_e rc_status;
    edgeclient_request_context_t *ctx = edgeclient_allocate_request_context(
            /* original uri */ "d/device-id/3303/10/5602",
            (uint8_t *) NULL,
            0,
            (uint8_t *) NULL,
            0,
            EDGECLIENT_VALUE_IN_BINARY,
            OPERATION_READ,
            LWM2M_OPAQUE,
            NULL,
            NULL,
            &rc_status,
            NULL);
    CHECK(ctx != NULL);
    CHECK_EQUAL(EDGE_RC_STATUS_SUCCESS, rc_status);
    edgeclient_deallocate_request_context(ctx);
}

TEST(edgeclient_request_context, test_allocate_request_context_correct_edge_core_uri)
{
    edge_rc_status_e rc_status;
    edgeclient_request_context_t *ctx = edgeclient_allocate_request_context(
            /* original uri */ "3/0/5",
            (uint8_t *) NULL,
            0,
            (uint8_t *) NULL,
            0,
            EDGECLIENT_VALUE_IN_BINARY,
            OPERATION_EXECUTE,
            LWM2M_OPAQUE,
            NULL,
            NULL,
            &rc_status,
            NULL);
    CHECK(ctx != NULL);
    CHECK_EQUAL(EDGE_RC_STATUS_SUCCESS, rc_status);
    edgeclient_deallocate_request_context(ctx);
}

TEST(edgeclient_request_context, test_allocate_request_context_null_uri)
{
    edge_rc_status_e rc_status;
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ NULL,
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_INVALID_PARAMETERS, rc_status);
}

TEST(edgeclient_request_context, test_allocate_request_context_empty_uri)
{
    edge_rc_status_e rc_status;
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_INVALID_PARAMETERS, rc_status);
}

TEST(edgeclient_request_context, test_allocate_request_context_invalid_uri)
{

    edge_rc_status_e rc_status;
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/invalid-uri/should-return-null",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);

    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "invalid-uri",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);
}

TEST(edgeclient_request_context, test_allocate_request_context_partial_uris)
{
    /* only device-id */

    edge_rc_status_e rc_status;
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);

    /* device-id and object id */
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id/3303",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);

    /* device-id, object-id and object-instance-id */
    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id/3303/10",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);
}

TEST(edgeclient_request_context, test_allocate_request_context_unparseable_ids)
{
    edge_rc_status_e rc_status;

    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id/object-id/instance-id/resource-id",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);

    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id/3303/instance-id/resource-id",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);

    CHECK(NULL == edgeclient_allocate_request_context(
                          /* original uri */ "d/device-id/3303/999/resource-id",
                          (uint8_t *) NULL,
                          0,
                          (uint8_t *) NULL,
                          0,
                          EDGECLIENT_VALUE_IN_BINARY,
                          OPERATION_READ,
                          LWM2M_OPAQUE,
                          NULL,
                          NULL,
                          &rc_status,
                          NULL));
    CHECK_EQUAL(EDGE_RC_STATUS_CANNOT_PARSE_URI, rc_status);
}
