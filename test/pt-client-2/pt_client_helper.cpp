#include "CppUTestExt/MockSupport.h"

extern "C" {
#include "pt-client-2/pt_client_helper.h"
}

void test_connection_ready_cb(connection_id_t connection_id, const char *name, void *userdata)
{
    // no-op
}

void test_connection_shutdown_cb(connection_id_t connection_id, void *userdata)
{
    // no-op
}

void test_success_handler(void *userdata)
{
    // no-op
}

void test_failure_handler(void *userdata)
{
    // no-op
}

void test_disconnected_cb(connection_id_t connection_id, void *userdata)
{
    mock().actualCall("test_disconnected_cb");
}

void test_certificate_renewal_notifier_cb(const connection_id_t connection_id,
                                          const char *name,
                                          int32_t initiator,
                                          int32_t status,
                                          const char *description,
                                          void *userdata)
{
    mock().actualCall("test_certificate_renewal_notifier_cb")
            .withStringParameter("name", name)
            .withIntParameter("initiator", initiator)
            .withIntParameter("status", status)
            .withStringParameter("description", description)
            .withPointerParameter("userdata", userdata);
}

pt_status_t test_device_certificate_renewal_request_handler(const connection_id_t connection_id,
                                                            const char *device_id,
                                                            const char *name,
                                                            void *userdata)
{
    return (pt_status_t) mock().actualCall("test_device_certificate_renewal_request_handler")
        .withStringParameter("device_id", device_id)
        .withStringParameter("name", name)
        .withPointerParameter("userdata", userdata)
        .returnIntValue();
}


pt_client_t *create_client(protocol_translator_callbacks_t *callbacks)
{
    return pt_client_create("/tmp/test-socket-path", callbacks);
}

void initialize_callbacks(protocol_translator_callbacks_t *callbacks)
{
    callbacks->connection_ready_cb = test_connection_ready_cb;
    callbacks->connection_shutdown_cb = test_connection_shutdown_cb;
    callbacks->certificate_renewal_notifier_cb = test_certificate_renewal_notifier_cb;
    callbacks->disconnected_cb = test_disconnected_cb;
    callbacks->device_certificate_renew_request_cb = test_device_certificate_renewal_request_handler;
}

