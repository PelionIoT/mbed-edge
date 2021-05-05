
#ifndef TEST_PT_CLIENT_HELPER_H
#define TEST_PT_CLIENT_HELPER_H

#include "pt-client-2/pt_common_api.h"
#include "pt-client-2/pt_client_api.h"

pt_client_t *create_client(protocol_translator_callbacks_t *callbacks);

/* Helper callbacks */
void initialize_callbacks(protocol_translator_callbacks_t *callbacks);
void test_connection_ready_cb(connection_id_t connection_id, const char *name, void *userdata);
void test_connection_shutdown_cb(connection_id_t connection_id, void *userdata);
void test_success_handler(void *userdata);
void test_failure_handler(void *userdata);
void test_disconnected_cb(connection_id_t connection_id, void *userdata);
void test_certificate_renewal_notifier_cb(const connection_id_t connection_id,
                                          const char *name,
                                          int32_t initiator,
                                          int32_t status,
                                          const char *description,
                                          void *userdata);
pt_status_t test_device_certificate_renewal_request_handler(const connection_id_t connection_id,
                                                            const char *device_id,
                                                            const char *name,
                                                            void *userdata);

#endif
