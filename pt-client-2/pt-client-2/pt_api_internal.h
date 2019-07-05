/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#ifndef PT_API_INTERNAL_H
#define PT_API_INTERNAL_H

#include <jansson.h>
#include <common/test_support.h>
#include "edge-rpc/rpc.h"
#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_devices_api.h"
#include "pt-client-2/pt_common_api_internal.h"
#include "pt-client-2/pt_devices_api_internal.h"
#include "pt-client-2/pt_device_api_internal.h"
#include "pt-client-2/pt_object_api_internal.h"
#include "pt-client-2/pt_object_instance_api_internal.h"
#include "pt-client-2/pt_resource_api_internal.h"
#include "pt-client-2/pt_certificate_api_internal.h"
#include "ns_list.h"
#include "common/edge_mutex.h"
#include "common/msg_api.h"

struct ctx_data;

typedef bool (*pt_f_close_condition)(pt_client_t *client, bool client_close);

struct pt_client_data_s {
    struct event_base *ev_base;
    pt_response_handler success_handler;
    pt_response_handler failure_handler;
    void *userdata;
    pt_devices_t *devices;
    const protocol_translator_callbacks_t *protocol_translator_callbacks;
    char *name;
    connection_id_t connection_id;
    int id;
    void *method_table;
    const char *socket_path;
    size_t json_flags;
    struct ctx_data *ctx_data;
    generate_msg_id generate_msg_id;
    pt_f_close_condition close_condition_impl;
    int backoff_time_in_sec;
    int tries;
    bool registered;
    bool close_client;
    bool close_connection;
    bool reconnection_triggered;
};
/*
struct pt_api_mutex_s {
    edge_mutex_t mutex;
    bool locked;
};
*/
typedef struct pt_customer_callback {
    connection_id_t connection_id;
    pt_response_handler success_handler;
    pt_response_handler failure_handler;
    void *userdata;
} pt_customer_callback_t;

typedef struct pt_device_customer_callback {
    connection_id_t connection_id;
    pt_device_response_handler success_handler;
    pt_device_response_handler failure_handler;
    void *userdata;
    char *device_id;
} pt_device_customer_callback_t;

typedef struct transport_connection {
    void *transport;
    write_func write_function;
} transport_connection_t;

typedef struct connection connection_t;

typedef struct {
    uint32_t num_failed;
    pt_devices_cb success_cb;
    pt_devices_cb failure_cb;
    connection_id_t connection_id;
    void *userdata;
} devices_cb_data_t;

typedef struct {
    devices_cb_data_t *common_data;
    bool last;
} device_cb_data_t;

/* Needed to convert the data type to customer callback */
typedef enum {
    PT_CUSTOMER_CALLBACK_T,        /* pt_customer_callback_t */
    PT_DEVICE_CUSTOMER_CALLBACK_T, /* pt_device_customer_callback_t */
} send_message_type_e;

typedef struct send_message_params {
    ns_list_link_t link;
    json_t *json_message;
    void *customer_callback_data;
    rpc_response_handler success_handler;
    rpc_response_handler failure_handler;
    rpc_free_func free_func;
    device_cb_data_t *device_cb_data_context;
    send_message_type_e type; // Used to determine type of customer_callback_data
} send_message_params_t;

typedef NS_LIST_HEAD(send_message_params_t, link) send_message_list_t;

int pt_client_read_data(connection_t *connection, char *data, size_t len);

extern struct jsonrpc_method_entry_t pt_service_method_table[];

typedef enum {
    PT_NOT_CHANGED,
    PT_CHANGED,
    PT_CHANGING,
} pt_changed_status_e;

struct pt_resource {
    ns_list_link_t link;
    pt_object_instance_t *parent;
    Lwm2mResourceType type;
    uint16_t id;
    uint8_t operations;
    uint8_t changed_status;
    uint8_t *value;
    uint32_t value_size;
    pt_userdata_t *userdata;
    // Callback for execute and write operations. Note: Execute and Write are exclusive. Therefore currently assuming
    // that a single callback is enough. See http://www.openmobilealliance.org/tech/profiles/LWM2M.xsd
    pt_resource_callback callback;
    // Callback for freeing the value buffer
    pt_resource_value_free_callback value_free;
};

typedef NS_LIST_HEAD(pt_resource_t, link) pt_resource_list_t;

struct pt_object_instance {
    ns_list_link_t link;
    pt_object_t *parent;
    pt_resource_list_t *resources;
    uint16_t id;
    uint8_t changed_status;
};

typedef NS_LIST_HEAD(pt_object_instance_t, link) pt_object_instance_list_t;

struct pt_object {
    ns_list_link_t link;
    pt_device_t *parent;
    pt_object_instance_list_t *instances;
    uint16_t id;
    uint8_t changed_status;
};

typedef NS_LIST_HEAD(pt_object_t, link) pt_object_list_t;

struct pt_device {
    ns_list_link_t link;
    struct pt_devices_data *devices_data;
    char *device_id;
    uint32_t lifetime;
    queuemode_t queuemode;
    pt_userdata_t *userdata;
    pt_object_list_t *objects;
    pt_device_state_e state;
    uint8_t changed_status;
    uint32_t features;
    char *csr_request_id;
    size_t csr_request_id_len;
};

typedef NS_LIST_HEAD(pt_device_t, link) pt_device_list_internal_t;

typedef struct pt_devices_data {
    pt_device_list_internal_t *list;
    uint8_t changed_status;
} pt_devices_data_t;

struct connection {
    ns_list_link_t link;
    // Move to websocket_connection_t
    struct lws_context *lws_context;
    transport_connection_t *transport_connection;
    connection_id_t id;
    pt_client_t *client;
    bool connected;
};

typedef NS_LIST_HEAD(connection_t, link) connection_list_t;

typedef struct {
    connection_id_t connection_id;
    json_t *response;
} response_params_t;

void destroy_connection_and_restart_reconnection_timer(connection_t *connection);

/**
 * \brief Initializes the connection structure between Device Management Edge and the connected
 * protocol translator.
 * \param client The Protocol Translator client instance created with `pt_client_create`.
 * \return The connection structure containing the connection-related data.
 */
connection_t *connection_init(pt_client_t *client);

/**
 * \brief Frees the data allocated in connection_init above.
 * \param connection A pointer to the connection to destroy.
 */
void connection_destroy(connection_t *connection);

/**
 * \brief Returns the ID of the connection.
 * \param connection The connection.
 * \return ID of the connection if it was found.
 *         PT_API_CONNECTION_ID_INVALID if the connection couldn't be found.
 */
connection_id_t get_connection_id(connection_t *connection);

/**
 * \brief Finds the connection given the connection ID.
 * \param connection_id The ID of the connection to look for.
 */
connection_t *find_connection(connection_id_t connection_id);

/**
 * \brief These mutex functions protect the pt_client_t instance and and its connection structure.
 */
 /*
void pt_api_lock_connection();
void pt_api_unlock_connection();
*/
/**
 * \brief These mutex functions protect the devices data of the client.
 */
 /*
void pt_api_lock_api_mutex(pt_client_t *client);
void pt_api_unlock_api_mutex(pt_client_t *client);
*/

void api_lock(void);
void api_unlock(void);

struct event_base *connection_get_ev_base(connection_t *connection);

/**
 * \brief Function pointer type definition for handling received message from Device Management Edge.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.\n
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread.\n
 * If the processing is run directly in the callback it will block the event loop and therefore it
 * will block the whole protocol translator.
 * The PT API mutex is automatically locked during this callback to protect devices data.
 *
 * \param connection_id The ID of the connection from which this write originates.
 * \param device_id The device ID to write the data.
 * \param object_id The object ID to write the data.
 * \param instance_id The instance ID to write the data.
 * \param resource_id The resource ID to write the data.
 * \param operation The operation of the write.
 * \param value The pointer to byte data to write.
 * \param value_size The length of the data.
 * \param userdata The pointer to user supplied data from `pt_client_start`.
 *
 * \return Returns 0 on success and non-zero on failure.
 */
typedef int (*pt_received_write_handler)(connection_id_t connection_id,
                                         const char *device_id,
                                         const uint16_t object_id,
                                         const uint16_t instance_id,
                                         const uint16_t resource_id,
                                         const unsigned int operation,
                                         const uint8_t *value,
                                         const uint32_t value_size,
                                         void *userdata);

/**
 * \brief Creates the devices list.
 */
pt_devices_t *pt_devices_create(pt_client_t *client);

/**
 * \brief Destroys the devices list.
 * It only destroys the list. Devices should have been freed already.
 * \param devices The structure which contains the device list.
 */
void pt_devices_destroy(pt_devices_t *devices);

/**
 * \brief Protocol translator registration function. Every protocol translator must register itself
 * with Device Management Edge before starting to handle endpoint related functions.
 *
 * \param connection_id The ID of the connection of the requesting application.
 * \param success_handler A function pointer to be called when the protocol translator registration
 * is successful.
 * \param failure_handler A function pointer to be called when the protocol translator registration
 * fails.
 * \param name The name of the protocol translator.
 * \param userdata The user-supplied context given as an argument to success and failure handler
 * functions.
 * \return The status of the protocol translator registration operation.\n
 *         `PT_STATUS_SUCCESS` on successful registration.\n
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_register_protocol_translator(connection_id_t connection_id,
                                            pt_response_handler success_handler,
                                            pt_response_handler failure_handler,
                                            const char *name,
                                            void *userdata);

pt_customer_callback_t *allocate_customer_callback(connection_id_t connection_id,
                                                   pt_response_handler success_handler,
                                                   pt_response_handler failure_handler,
                                                   void *userdata);

void customer_callback_free_func(rpc_request_context_t *callback_data);

pt_status_t construct_and_send_outgoing_message(connection_id_t connection_id,
                                                json_t *json_message,
                                                rpc_response_handler success_handler,
                                                rpc_response_handler failure_handler,
                                                rpc_free_func free_func,
                                                send_message_type_e type,
                                                void *customer_callback_data);

send_message_params_t *construct_outgoing_message(json_t *json_message,
                                                  rpc_response_handler success_handler,
                                                  rpc_response_handler failure_handler,
                                                  rpc_free_func free_func,
                                                  send_message_type_e type,
                                                  void *customer_callback_data,
                                                  pt_status_t *status);

pt_status_t send_message_to_event_loop(connection_id_t connection_id, send_message_params_t *message);

void event_loop_send_response_callback(void *data);

/**
 * \brief May be called from any thread to send a message to the event-loop thread.
 * \param connection_id The connection id. If finds the event loop base pointer from this.
 * \param parameter.
 * \param callback The callback to call in the event loop with the parameter.
 */
pt_status_t pt_api_send_to_event_loop(connection_id_t connection_id, void *parameter, event_loop_callback_t callback);

#ifdef BUILD_TYPE_TEST
extern edge_mutex_t api_mutex;
#include "common/websocket_comm.h"

bool default_check_close_condition(pt_client_t *client, bool client_close);
void create_connection_cb(void *arg);
void pt_client_shutdown_cb(void *arg);
void pt_client_disconnected_cb(void *arg);
int pt_client_write_data(connection_t *connection, char *data, size_t len);
void websocket_disconnected(websocket_connection_t *websock_conn);
bool create_client_connection(pt_client_t *client);
int callback_edge_client_protocol_translator(struct lws *wsi,
                                             enum lws_callback_reasons reason,
                                             void *user,
                                             void *in,
                                             size_t len);
void pt_client_set_msg_id_generator(pt_client_t *client, generate_msg_id generate_msg_id);
void websocket_connection_t_destroy(websocket_connection_t **wct);
void transport_connection_t_destroy(transport_connection_t **transport_connection);
void event_loop_send_message_callback(void *arg);
void pt_reset_api();
void pt_handle_pt_register_success(json_t *response, void *callback_data);
void pt_handle_pt_register_failure(json_t *response, void *callback_data);
void pt_handle_device_register_success(json_t *response, void *callback_data);
void pt_handle_device_register_failure(json_t *response, void *callback_data);
void pt_handle_device_unregister_success(json_t *response, void *callback_data);
void pt_handle_device_unregister_failure(json_t *response, void *callback_data);
void pt_handle_pt_write_value_success(json_t *response, void* userdata);
void pt_handle_pt_write_value_failure(json_t *response, void* userdata);

pt_status_t check_registration_data_allocated(json_t *register_msg,
                                              json_t *params,
                                              json_t *j_objects,
                                              json_t *device_lifetime,
                                              json_t *device_queuemode,
                                              json_t *device_id,
                                              struct pt_device_customer_callback *customer_callback);

pt_status_t check_unregistration_data_allocated(json_t *unregister_msg,
                                                json_t *params,
                                                json_t *device_id,
                                                struct pt_device_customer_callback *customer_callback);

pt_device_customer_callback_t *allocate_device_customer_callback(connection_id_t connection_id,
                                                                 pt_device_response_handler success_handler,
                                                                 pt_device_response_handler failure_handler,
                                                                 const char *device_id,
                                                                 void *userdata);
void device_customer_callback_free(pt_device_customer_callback_t *callback);
pt_status_t write_data_frame(send_message_params_t *message);
pt_status_t check_write_value_data_allocated(json_t *request,
                                             json_t *params,
                                             json_t *j_objects,
                                             json_t *device_id,
                                             struct pt_device_customer_callback *customer_callback);

void device_customer_callback_free_func(rpc_request_context_t *callback_data);

void pt_init_check_close_condition_function(pt_client_t *client, pt_f_close_condition func);

// Service API
int pt_receive_write_value(json_t *request, json_t *json_params, json_t **result, void *userdata);
int pt_receive_certificate_renewal_result(json_t *request, json_t *json_params, json_t **result, void *userdata);

#endif

#endif
