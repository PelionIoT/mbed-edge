#ifndef SERVER_TEST_H
#define SERVER_TEST_H

#include <stddef.h>

struct connection *server_test_establish_connection();
void server_test_free_established_connection(struct connection *connection);
void server_test_call_receive_cb(struct connection *connection, void *data, size_t len);
void server_test_connection_closed(struct connection *connection);
int server_test_connection_filter_cb(const char *uri);
#endif
