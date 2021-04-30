#ifndef CLIENT_SEND_RECEIVE_HELPER_H
#define CLIENT_SEND_RECEIVE_HELPER_H
extern "C" {
#include "pt-client-2/pt_common_api.h"
#include "common/default_message_id_generator.h"
#include "pt-client-2/pt_api_internal.h"
}
#include "cpputest-custom-types/value_pointer.h"
#include <stdbool.h>

extern connection_id_t active_connection_id;
extern connection_t *active_connection;
extern int32_t rpc_id_counter;
char *test_msg_generate_id();
void reset_rpc_id_counter();
void process_event_loop_send_message(bool connection_found);
void process_event_loop_send_response();
ValuePointer *expect_outgoing_data_frame(const char *data);
int test_write_function(struct connection *connection, char *data, size_t len);
void receive_incoming_data_frame_expectations();
void find_client_device_expectations();
void receive_incoming_data_frame(connection_t *active_connection, const char *data);
void expect_msg_api_message();
void expect_msg_api_message_sending_fails();
void process_event_loop_send_message(bool connection_found);
connection_id_t create_client_connection();
void destroy_connection(connection_t *connection);
pt_client_t *destroy_active_connection();
void destroy_client(pt_client_t *client);
void free_client_and_connection(connection_id_t connection_id);

#endif
