/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
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

#define TRACE_GROUP "edgecc"

extern "C" {
#include "common/integer_length.h"
#include "edge-core/edge_server.h"
#include "common/msg_api.h"
}
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "pal.h"
#include "fcc_defs.h"
#include "factory_configurator_client.h"
#include "mbed_cloud_client_user_config.h"
#include "key_config_manager.h"
#include "common/pt_api_error_codes.h"
#include "common/constants.h"
#include "common/test_support.h"
#include "common/edge_mutex.h"
#include "edge-client/edge_client.h"
extern "C" {
#include "edge-client/edge_client_format_values.h"
}
#include "edge-client/edge_client_impl.h"
#include "edge-client/edge_client_internal.h"
#include "edge-client/edge_client_byoc.h"
#include "edge-client/edge_core_cb.h"
#include "edge-client/async_cb_params.h"
#include "edge-client/async_cb_params_base.h"
#include "edge-client/eventloop_tracing.h"
#include "edge-client/edge_client_mgmt.h"
#include "edge-client/request_context.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mstring.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mvector.h"
#include "ns_event_loop.h"
#include "include/m2mcallbackstorage.h"

EDGE_LOCAL EdgeClientImpl *client = NULL;
edgeclient_data_t *client_data = NULL;
EDGE_LOCAL void destroy_resource_list(Vector<ResourceListObject_t *> &list);
EDGE_LOCAL void setup_config_mountdir();
EDGE_LOCAL Lwm2mResourceType resolve_m2mresource_type(M2MResourceBase::ResourceType resourceType);
EDGE_LOCAL void edgeclient_handle_async_coap_request_cb(const M2MBase &base,
                                                        M2MBase::Operation operation,
                                                        const uint8_t *token,
                                                        const uint8_t token_len,
                                                        const uint8_t *buffer,
                                                        size_t buffer_size,
                                                        void *client_args);
EDGE_LOCAL void edgeclient_on_est_status_callback(est_enrollment_result_e result,
                                                  struct cert_chain_context_s *cert_chain,
                                                  void *context);


typedef bool (*context_check_fn)(struct context *checked_ctx, struct context *given_ctx);

EDGE_LOCAL void edgeclient_data_init()
{
    client_data = new edgeclient_data_s();
    tr_debug("edgeclient_data_init %p", client_data);
}

EDGE_LOCAL void edgeclient_data_free()
{
    tr_debug("edgeclient_data_free %p", client_data);
    delete client_data;
    client_data = NULL;
}

EDGE_LOCAL void destroy_base_list(M2MBaseList &list)
{
    int32_t i;
    for(i = 0; i< list.size(); i++)
    {
        delete list[i];
        list.erase(i);
        i--;
    }
}

edgeclient_data_s::~edgeclient_data_s()
{
    destroy_base_list(pending_objects);
    destroy_base_list(registered_objects);
    destroy_base_list(registering_objects);
    destroy_resource_list(resource_list);
}


EDGE_LOCAL void destroy_resource_list(Vector<ResourceListObject_t *> &list)
{
    int32_t i = 0;
    for(i = 0; i < list.size(); i++)
    {
        if (list[i]->acp) {
            delete list[i]->acp;
        }
        delete list[i];
        list.erase(i);
        i--;
    }
}

EDGE_LOCAL void edgeclient_execute_success(edgeclient_request_context_t *ctx)
{
    tr_info("Execute successful to protocol translator for path 'd/%s/%d/%d/%d'.",
            ctx->device_id,
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    edgeclient_send_asynchronous_response(ctx->device_id,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          COAP_RESPONSE_CHANGED);
    edgeclient_deallocate_request_context(ctx);
}

EDGE_LOCAL void edgeclient_execute_failure(edgeclient_request_context_t *ctx)
{
    tr_info("Execute failed to protocol translator for path 'd/%s/%d/%d/%d'.",
            ctx->device_id,
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    coap_response_code_e coap_response_code = map_to_coap_error(ctx->jsonrpc_error_code);
    edgeclient_send_asynchronous_response(ctx->device_id,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response_code);
    edgeclient_deallocate_request_context(ctx);
}

EDGE_LOCAL void edgeclient_write_success(edgeclient_request_context_t *ctx)
{
    coap_response_code_e coap_response = COAP_RESPONSE_CHANGED;
    pt_api_result_code_e status = edgeclient_update_resource_value(ctx->device_id,
                                                                   ctx->object_id,
                                                                   ctx->object_instance_id,
                                                                   ctx->resource_id,
                                                                   ctx->value,
                                                                   ctx->value_len);
    if (PT_API_SUCCESS != status) {
        tr_err("edgeclient_write_success: updating written value failed with code %d", status);
        switch (status) {
            case PT_API_RESOURCE_NOT_FOUND: {
                coap_response = COAP_RESPONSE_NOT_FOUND;
            } break;
            case PT_API_ILLEGAL_VALUE: {
                coap_response = COAP_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
            } break;
            default: {
                coap_response = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
            } break;
        }
    }
    edgeclient_send_asynchronous_response(ctx->device_id,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response);
    edgeclient_deallocate_request_context(ctx);
}

EDGE_LOCAL coap_response_code_e map_to_coap_error(int16_t jsonrpc_error_code)
{
    coap_response_code_e resp;
    switch (jsonrpc_error_code) {
        case PT_API_REQUEST_TIMEOUT:
            resp = COAP_RESPONSE_GATEWAY_TIMEOUT;
            break;
        case PT_API_REMOTE_DISCONNECTED:
            resp = COAP_RESPONSE_NOT_FOUND;
            break;
        default:
            resp = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
            break;
    }
    return resp;
}

EDGE_LOCAL void edgeclient_write_failure(edgeclient_request_context_t *ctx)
{
    tr_warn("Writing to protocol translator failed");
    coap_response_code_e coap_response_code = map_to_coap_error(ctx->jsonrpc_error_code);
    edgeclient_send_asynchronous_response(ctx->device_id,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response_code);
    edgeclient_deallocate_request_context(ctx);
}

bool edgeclient_endpoint_value_execute_handler(const M2MResourceBase *resource_base,
                                               void *endpoint_context,
                                               uint8_t *buffer,
                                               const uint32_t length,
                                               uint8_t *token,
                                               uint8_t token_len,
                                               edge_rc_status_e *rc_status)
{
    Lwm2mResourceType resource_type = resolve_m2mresource_type(resource_base->resource_instance_type());
    const char *uri = resource_base->uri_path();
    uint8_t operation = OPERATION_EXECUTE;

    tr_info("resource async request: operation=%d url=%s, data length=%d", (int32_t) operation, uri, (int32_t) length);

    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri,
                                                                                    buffer,
                                                                                    length,
                                                                                    token,
                                                                                    token_len,
                                                                                    EDGECLIENT_VALUE_IN_BINARY,
                                                                                    (uint8_t) operation,
                                                                                    resource_type,
                                                                                    edgeclient_execute_success,
                                                                                    edgeclient_execute_failure,
                                                                                    rc_status,
                                                                                    endpoint_context);

    if (request_ctx) {
        if (0 == edgeclient_write_to_pt_cb(request_ctx, endpoint_context)) {
            return true;
        } else {
            tr_err("Executing to protocol translator failed.");
            edgeclient_deallocate_request_context(request_ctx);
        }
    } else {
        tr_err("Could not allocate request context for writing to protocol translator.");
        free(buffer);
    }
    return false;
}

bool edgeclient_endpoint_value_set_handler(const M2MResourceBase *resource_base,
                                           void *endpoint_context,
                                           uint8_t *value,
                                           const uint32_t value_length,
                                           uint8_t *token,
                                           uint8_t token_len,
                                           edge_rc_status_e *rc_status)
{
    const char *uri_path = resource_base->uri_path();
    Lwm2mResourceType resource_type = resolve_m2mresource_type(resource_base->resource_instance_type());
    tr_info("Value write initiated to protocol translator for %s with size %u", uri_path, value_length);

    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri_path,
                                                                                    value,
                                                                                    value_length,
                                                                                    token,
                                                                                    token_len,
                                                                                    EDGECLIENT_VALUE_IN_TEXT,
                                                                                    OPERATION_WRITE,
                                                                                    resource_type,
                                                                                    edgeclient_write_success,
                                                                                    edgeclient_write_failure,
                                                                                    rc_status,
                                                                                    endpoint_context);
    if (request_ctx) {
        // below actually calls write_to_pt in protocol_api.c
        if (0 != edgeclient_write_to_pt_cb(request_ctx, endpoint_context)) {
            tr_err("Write failed. Freeing the request context.");
            edgeclient_deallocate_request_context(request_ctx);
            return false;
        }
        return true;
    } else {
        tr_err("Could not allocate request context. Write not propagated to protocol translator.");
        free(value);
    }
    return false;
}

#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
EDGE_LOCAL void list_objects_sub(const char *objects_name, M2MBaseList &objects)
{
    tr_debug("  %s:", objects_name);
    M2MBaseList::iterator it;

    for (it = objects.begin(); it != objects.end(); it++) {
        /*
         * Must call the function `name()`, tests expect that it gets called.
         * This causes compiler warning when debug logs are disabled,
         * the preprocessor drops out the `tr_debug()`.
         */
        const char* name = (*it)->name();
        tr_debug("    %s", name);
    }
}

EDGE_LOCAL void list_objects()
{
    list_objects_sub("pending objects", client_data->pending_objects);
    list_objects_sub("registering objects", client_data->registering_objects);
    list_objects_sub("registered objects", client_data->registered_objects);
}
#endif

EDGE_LOCAL void edgeclient_update_register_msg_cb(void *arg)
{
    (void) arg;
    tr_debug("edgeclient_update_register_msg_cb");
    edgeclient_update_register_conditional();
}

EDGE_LOCAL void edgeclient_send_update_register_conditional_message()
{
    struct event_base *base = edge_server_get_base();
    if (!msg_api_send_message(base, NULL, edgeclient_update_register_msg_cb)) {
        tr_err("edgeclient_send_update_register_conditional_message - cannot send message!");
    }
}

// This method is "safe", because it's called from libevent event loop, preventing e.g. race-conditions.
EDGE_LOCAL void edgeclient_on_registered_callback_safe(void *arg)
{
    (void) arg;
    tr_debug("edgeclient_on_registered_callback client_data = %p", client_data);
    bool start_registration = edgeclient_is_registration_needed();
    tr_debug("on_registered_callback");
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    // Move newly registered objects to registered list
    client_data->edgeclient_status = REGISTERED;
    tr_debug("on_registered_callback, registered %d objects", client_data->registering_objects.size());
    M2MBaseList::iterator it;
    for (it = client_data->registering_objects.begin(); it != client_data->registering_objects.end(); it++) {
        // Check: !Endpoint or (Endpoint and not deleted)
        bool is_endpoint = (*it)->base_type() == M2MBase::ObjectDirectory;
        if (!is_endpoint || (is_endpoint && !(*it)->is_deleted())) {
            client_data->registered_objects.push_back(*it);
        } else {
            // Remove from client
            client->remove_object(*it);
            delete (*it);
        }
    }
    // And clear registering_objects for next register update
    client_data->registering_objects.clear();
    tr_debug("on_registered_callback, pending objects count %d", client_data->pending_objects.size());
    // Move pending objects to be registered if there is any
    if (!client_data->pending_objects.empty()) {
        start_registration = true;
    }
    client_data->g_handle_register_cb();
    // Protocol API will reject incoming registrations from protocol translators when edge core is shutting down so this
    // should not keep looping due to new devices
    if (client->is_interrupt_received() && !start_registration) {
        edgeserver_graceful_shutdown();
    }
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    tr_debug("on_registered_callback, after list handling.");
    list_objects();
#endif

    if (start_registration) {
        edgeclient_send_update_register_conditional_message();
    }
}

EDGE_LOCAL void edgeclient_on_registered_callback(void)
{
    struct event_base *base = edge_server_get_base();
    if (!msg_api_send_message(base, NULL, edgeclient_on_registered_callback_safe)) {
        tr_err("edgeclient_on_registered_callback - cannot send message!");
    }
}

EDGE_LOCAL void edgeclient_on_unregistered_callback_safe(void *arg)
{
    tr_debug("on_unregistered_callback_safe");
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    client_data->edgeclient_status = UNREGISTERED;

    client_data->g_handle_unregister_cb();
}

EDGE_LOCAL void edgeclient_on_unregistered_callback(void)
{
    struct event_base *base = edge_server_get_base();
    if (!msg_api_send_message(base, NULL, edgeclient_on_unregistered_callback_safe)) {
        tr_err("edgeclient_on_unregistered_callback - cannot send message!");
    }
}

void edgeclient_on_error_callback_safe(edgeclient_error_callback_params_t *params)
{
    tr_debug("on_error_callback_safe");
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    client_data->edgeclient_status = ERROR;

    client_data->g_handle_error_cb(params->error_code, params->error_description);
    free(params);
}

void edgeclient_on_error_callback(int error_code, const char *error_description)
{
    struct event_base *base = edge_server_get_base();
    edgeclient_error_callback_params_t *params = (edgeclient_error_callback_params_t *)
            calloc(1, sizeof(edgeclient_error_callback_params_t));
    if (params) {
        params->error_code = error_code;
        params->error_description = error_description;
        if (msg_api_send_message(base, params, (event_loop_callback_t) edgeclient_on_error_callback_safe)) {
            return;
        } else {
            free(params);
        }
    }
    tr_err("edgeclient_on_error_callback - cannot send message!");
}

EDGE_LOCAL void edgeclient_on_certificate_renewal_callback(const char *certificate_name,
                                                           ce_status_e status,
                                                           ce_initiator_e initiator)
{
    int ret_val = client_data->g_handle_cert_renewal_status_cb(certificate_name, status, initiator, client_data->g_cert_renewal_ctx);
    (void) ret_val;
    // TODO FIXME: what to do if the protocol translator write failed?
}

pt_api_result_code_e edgeclient_renew_certificate(const char *certificate_name, int *detailed_error)
{
    pt_api_result_code_e ret = PT_API_SUCCESS;
    if (client != NULL) {
        ce_status_e status = client->certificate_renew(certificate_name);
        if (detailed_error != NULL) {
            *detailed_error = status;
        }
        if (status != CE_STATUS_SUCCESS) {
            ret = PT_API_CERTIFICATE_RENEWAL_ERROR;
            if (status == CE_STATUS_DEVICE_BUSY) {
                ret = PT_API_CERTIFICATE_RENEWAL_BUSY;
            }
        }
    }
    return ret;
}

/**
 * \brief remove objects which are matching the given context.
 * \param list is the list to search
 * \param context is the context to match
 * \return number of objects removed
 */
EDGE_LOCAL uint32_t edgeclient_remove_objects_from_list(M2MBaseList &list, void *context, context_check_fn check_fn)
{
    int32_t removed_count = 0;
    int index = 0;
    tr_debug("remove_objects_from_list: list: %p, context: %p", &list, context);
    while (index < list.size()) {
        M2MBase *base = list[index];
        assert(base != NULL);
        tr_debug("[%d]  iterating %p %s", index, base, base->name());
        M2MEndpoint *endpoint = NULL;
        M2MObject *object = NULL;
        if (base->base_type() == M2MBase::ObjectDirectory) {
            endpoint = dynamic_cast<M2MEndpoint *>(base);
        } else {
            object = dynamic_cast<M2MObject *>(base);
            if (object) {
                endpoint = object->get_endpoint();
            }
        }
        if (endpoint && (*check_fn)((struct context *)(endpoint->get_context()), (struct context *)context)) {
            tr_debug("Removing object %p", base);
            client->remove_object(base);
            list.erase(index);
            removed_count++;
            delete base;
        } else {
            index++;
        }
    }
    return removed_count;
}

EDGE_LOCAL bool check_context_matches(struct context *checked_ctx, struct context *given_ctx)
{
    return (checked_ctx == given_ctx);
}

EDGE_LOCAL bool check_context_is_not_null(struct context *checked_ctx, struct context *given_ctx)
{
    return (checked_ctx != NULL);
}

bool edgeclient_remove_resources_owned_by_client(void *context)
{
    int index = 0;
    tr_debug("remove_resources_from_list: list: %p, context: %p", &client_data->resource_list, context);
    while (index < client_data->resource_list.size()) {
        ResourceListObject_t *resource_list_object = client_data->resource_list[index];
        tr_debug("  iterating resource_list_object: %p", resource_list_object);
        if (resource_list_object->connection == context) {
            tr_debug("  remove resource list object: %p", resource_list_object);
            client_data->resource_list.erase(index);
            if (resource_list_object->acp) {
                delete resource_list_object->acp;
            }
            delete resource_list_object;
            // Note: we cannot delete the resource here, because the resource destructor is private!
        } else {
            index++;
        }
    }
    return true;
}

uint32_t edgeclient_remove_objects_owned_by_client(void *client_context)
{
    uint32_t total_removed = 0;
    total_removed += edgeclient_remove_objects_from_list(
            client_data->registered_objects, client_context, &check_context_matches);
    total_removed += edgeclient_remove_objects_from_list(
            client_data->pending_objects, client_context, &check_context_matches);
    total_removed += edgeclient_remove_objects_from_list(
            client_data->registering_objects, client_context, &check_context_matches);
    if (total_removed > 0) {
        edgeclient_set_update_register_needed();
    }
    return total_removed;
}

EDGE_LOCAL uint32_t remove_all_endpoints()
{
    uint32_t total_removed = 0;
    total_removed +=
            edgeclient_remove_objects_from_list(client_data->registered_objects, NULL, &check_context_is_not_null);
    total_removed +=
            edgeclient_remove_objects_from_list(client_data->pending_objects, NULL, &check_context_is_not_null);
    total_removed +=
            edgeclient_remove_objects_from_list(client_data->registering_objects, NULL, &check_context_is_not_null);
    if (total_removed > 0) {
        edgeclient_set_update_register_needed();
    }
    return total_removed;
}

bool edgeclient_stop()
{
    bool ret_val = true;
    if (!client->is_interrupt_received()) {
        client->set_interrupt_received();
        bool translators_removed = edgeserver_remove_protocol_translator_nodes();
        uint32_t endpoints_removed = remove_all_endpoints();
        if (client_data->edgeclient_status == REGISTERED && edgeclient_is_registration_needed()) {
            tr_info("edgeclient_stop - removing %u endpoints translators_removed=%d",
                    endpoints_removed,
                    (int32_t) translators_removed);
            edgeclient_update_register();
        } else {
            // If registering is already in progress, just wait for the callback
            if (client_data->edgeclient_status != REGISTERING) {
                tr_info("edgeclient_stop - initiating graceful shutdown when edgeclient status is %d",
                        (int32_t)(client_data->edgeclient_status));
                edgeserver_graceful_shutdown();
            }
        }
    } else {
        tr_error("edgeclient_stop - 2nd interrupt received. Exiting immediately!");
        edgeserver_exit_event_loop();
        ret_val = false;
    }
    return ret_val;
}

void edgeclient_create(const edgeclient_create_parameters_t *params, byoc_data_t *byoc_data)
{
    tr_info("create_client()");
    if (client == NULL) {
        setup_config_mountdir();
        eventloop_stats_init();
        edgeclient_setup_credentials(params->reset_storage, byoc_data);
        client = new EdgeClientImpl();
        edgeclient_data_init();

        client_data->g_handle_write_to_pt_cb = params->handle_write_to_pt_cb;
        client_data->g_handle_register_cb = params->handle_register_cb;
        client_data->g_handle_unregister_cb = params->handle_unregister_cb;
        client_data->g_handle_error_cb = params->handle_error_cb;
        client_data->g_handle_cert_renewal_status_cb = params->handle_cert_renewal_status_cb;
        client_data->g_cert_renewal_ctx = params->cert_renewal_ctx;
        client_data->g_handle_est_status_cb = params->handle_est_status_cb;
        client->set_on_registered_callback(edgeclient_on_registered_callback);
        client->set_on_registration_updated_callback(edgeclient_on_registered_callback);
        client->set_on_unregistered_callback(edgeclient_on_unregistered_callback);
        client->set_on_error_callback(edgeclient_on_error_callback);
        client->set_on_certificate_renewal_callback(edgeclient_on_certificate_renewal_callback);
        client->set_on_est_result_callback(edgeclient_on_est_status_callback);
        tr_debug("create_client - client = %p", client);
    }
}

/* The unistd and usleep are introduced for a workaround to wait
 * underlying pal/pthread shutdown of eventOS.
 * The waiting of thread shutdown relies on semaphores, the event
 * loop thread releases the semaphore that is waited on the thread
 * which set the stop flag.
 */
#include <unistd.h>
#ifndef BUILD_TYPE_TEST
#define SHUTDOWN_USECS 500000 // 500 ms
#else
#define SHUTDOWN_USECS 1000 // 1 ms
#endif
void edgeclient_destroy()
{
    tr_debug("edgeclient_destroy %p", client);
    if (client != NULL) {
        edgeclient_data_free();
        delete client;
        client = NULL;
        fcc_finalize();
        ns_event_loop_thread_stop();
        /*
         * The workaround for waiting that underlying threads from Cloud Client are freed.
         */
        unsigned int usecs = SHUTDOWN_USECS;
        tr_warn("edgeclient_destroy: sleeping for %d ms for shutdown.", usecs / 1000);
        usleep(usecs);
    }
}

void edgeclient_connect() {
    bool start_registration = false;
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    if (client_data->edgeclient_status != REGISTERING) {
        tr_info("connect_client() status = %d", client_data->edgeclient_status);
        edgeclient_add_client_objects_for_registering();
        // Start registration
        client_data->edgeclient_status = REGISTERING;
        start_registration = true;
    }
    else {
        tr_debug("Client already registering, defer registration");
    }
    if (start_registration) {
        client->start_registration();
    }
}

void edgeclient_update_register_conditional()
{
    tr_debug("update_register_client_conditional");
    if (edgeclient_is_registration_needed()) {  // atomic
        edgeclient_update_register();
    }
}

void edgeclient_update_register()
{
    bool start_registration = false;
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    if (client_data->edgeclient_status == REGISTERED) {
        tr_debug("update_register_client() status = %d", client_data->edgeclient_status);
        edgeclient_add_client_objects_for_registering();
        // Mark the flag to false after adding objects for registering.
        // The function `edgeclient_add_client_objects_for_registering()`
        // sets `client_data->m2m_resources_added_or_removed`
        // to true. When registering starts this value must be set to false.
        client_data->m2m_resources_added_or_removed = false;
        client_data->edgeclient_status = REGISTERING;
        start_registration = true;
    }
    else {
        tr_debug("Client already registering, defer registration");
    }
    if (start_registration) {
        client->start_update_registration();
    }
}

bool edgeclient_endpoint_exists(const char *endpoint_name) {
    bool ret = true;
    if (edgeclient_get_endpoint(endpoint_name) == NULL) {
        ret = false;
    }
    return ret;
}

void edgeclient_add_object_to_registration(M2MBase *object)
{
    if (object == NULL) {
        return;
    }
    client_data->pending_objects.push_back(object);
    edgeclient_set_update_register_needed();
}

bool edgeclient_add_endpoint(const char *endpoint_name, void *ctx) {
    tr_debug("add_endpoint %s", endpoint_name);
    if (endpoint_name == NULL || edgeclient_get_endpoint(endpoint_name) != NULL) {
        return false;
    }
    M2MEndpoint *new_ep = M2MInterfaceFactory::create_endpoint(String(endpoint_name));
    if (new_ep == NULL) {
        tr_error("M2MInterfaceFactory::create_endpoint failed.");
        return false;
    }
    new_ep->set_context(ctx);
    edgeclient_add_object_to_registration((M2MBase*)new_ep);
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    return true;
}

bool edgeclient_remove_endpoint(const char *endpoint_name)
{
    int found_index;
    bool found = false;
    M2MBaseList *found_list;
    edgeclient_set_update_register_needed();
    tr_debug("Remove endpoint %s", endpoint_name);
    M2MEndpoint *endpoint = edgeclient_get_endpoint_with_index(endpoint_name, &found_list, &found_index);
    // Remove from list
    if (endpoint) {
        found = true;
        (*found_list).erase(found_index);
    }
    client_data->pending_objects.push_back(endpoint);
    // Mark deleted, ultimate deletion happens in registration update callback.
    if (endpoint) {
        endpoint->set_deleted();
    }
    return found;
}

bool edgeclient_add_object(const char *endpoint_name, const uint16_t object_id) {
    tr_debug("add_object");
    char object_name[6] = {0};

    tr_debug("add_object %d to %s", object_id, endpoint_name);

    m2m::itoa_c(object_id, object_name);
    String object_str(object_name);
    if (endpoint_name != NULL) {
        M2MEndpoint *ep = edgeclient_get_endpoint(endpoint_name);
        if (ep == NULL) {
            return false;
        }
        M2MObject *obj = ep->create_object(object_str);
        if (obj == NULL) {
            return false;
        }
        obj->set_endpoint(ep);
    }
    else {
        M2MObject *obj = M2MInterfaceFactory::create_object(object_str);
        if (obj == NULL) {
            return false;
        }
        edgeclient_add_object_to_registration((M2MBase*)obj);
    }
#ifdef CLOUD_CLIENT_LIST_OBJECT_DEBUG
    list_objects();
#endif
    return true;
}

bool edgeclient_add_object_instance(const char *endpoint_name,
                                    const uint16_t object_id,
                                    const uint16_t object_instance_id)
{

    tr_debug("add_object_instance %d to %s", object_id, endpoint_name);

    if (edgeclient_get_object_instance(endpoint_name, object_id, object_instance_id) != NULL) {
        return false;
    }
    M2MObject *obj = edgeclient_get_object(endpoint_name, object_id);
    if (obj == NULL) {
        return false;
    }
    M2MObjectInstance *inst = obj->create_object_instance(object_instance_id);
    if (inst == NULL) {
        return false;
    }
    return true;
}

bool edgeclient_remove_object_instance(const char *endpoint_name,
                                       const uint16_t object_id,
                                       const uint16_t object_instance_id)
{
    bool ret = false;
    M2MObject *object = edgeclient_get_object(endpoint_name, object_id);

    if (object) {
        ret = object->remove_object_instance(object_instance_id);
    }
    return ret;
}

EDGE_LOCAL Lwm2mResourceType resolve_m2mresource_type(M2MResourceBase::ResourceType resourceType)
{
    switch (resourceType) {
    case M2MResourceBase::STRING:
        return LWM2M_STRING;
    case M2MResourceBase::INTEGER:
        return LWM2M_INTEGER;
    case M2MResourceBase::FLOAT:
        return LWM2M_FLOAT;
    case M2MResourceBase::BOOLEAN:
        return LWM2M_BOOLEAN;
    case M2MResourceBase::OPAQUE:
        return LWM2M_OPAQUE;
    case M2MResourceBase::TIME:
        return LWM2M_TIME;
    case M2MResourceBase::OBJLINK:
        return LWM2M_OBJLINK;
    }
    return static_cast<Lwm2mResourceType>(-1);
}

EDGE_LOCAL M2MResourceBase::ResourceType resolve_resource_type(Lwm2mResourceType resourceType)
{
    switch (resourceType) {
        case LWM2M_STRING:
            return M2MResourceBase::STRING;
        case LWM2M_INTEGER:
            return M2MResourceBase::INTEGER;
        case LWM2M_FLOAT:
            return M2MResourceBase::FLOAT;
        case LWM2M_BOOLEAN:
            return M2MResourceBase::BOOLEAN;
        case LWM2M_OPAQUE:
            return M2MResourceBase::OPAQUE;
        case LWM2M_TIME:
            return M2MResourceBase::TIME;
        case LWM2M_OBJLINK:
            return M2MResourceBase::OBJLINK;
    }
    return static_cast<M2MResourceBase::ResourceType>(-1);
}

bool edgeclient_add_resource(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id,
                  const uint16_t resource_id, Lwm2mResourceType resource_type, int opr, void *connection)
{
    AsyncCallbackParamsBase *acp = NULL;
    tr_debug("add_resource for endpoint: %s, object_id: %u, object_instance_id: %u, resource_id: %u",
             endpoint_name,
             object_id,
             object_instance_id,
             resource_id);
    if (edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id) != NULL) {
        return false;
    }

    M2MObjectInstance *inst = edgeclient_get_object_instance(endpoint_name, object_id, object_instance_id);
    if (inst == NULL) {
        return false;
    }
    char res_name[6] = {0};

    m2m::itoa_c(resource_id, res_name);
    M2MResourceBase::ResourceType resolved_resource_type = resolve_resource_type(resource_type);
    M2MResource *res = inst->create_dynamic_resource(String(res_name), "", resolved_resource_type, true, false, false);
    if (res == NULL) {
        return false;
    }
    res->set_operation((M2MBase::Operation) opr);

    if (opr & (OPERATION_EXECUTE | OPERATION_WRITE)) {
        void *context = NULL;

        M2MObject *object = edgeclient_get_object(endpoint_name, object_id);
        if (object == NULL) {
            tr_err("Could not get the object %s, %d", endpoint_name, object_id);
            return false;
        }

        M2MEndpoint *endpoint = object->get_endpoint();
        if (endpoint) {
            context = endpoint->get_context();
        }
        if (context) {
            if (endpoint_name == NULL) {
                tr_err("Got context without endpoint name - Illegal state!");
                return false;
            }
            acp = (AsyncCallbackParamsBase *) new AsyncCallbackParams(context);
            if (!((AsyncCallbackParams *) acp)->set_uri(endpoint_name, object_id, object_instance_id, resource_id)) {
                tr_err("Cannot set the uri for endpoint resource - setting execute callback failed!");
                delete acp;
                return false;
            }
        } else {
            acp = (AsyncCallbackParamsBase *) new EdgeCoreCallbackParams();
            if (!((EdgeCoreCallbackParams *) acp)->set_uri(object_id, object_instance_id, resource_id)) {
                tr_err("Cannot set the uri for Edge Core resource - setting execute callback failed!");
                delete acp;
                return false;
            }
        }
        res->set_async_coap_request_cb(edgeclient_handle_async_coap_request_cb, acp);
    }
    // need to reclaim this memory when resource is removed
    ResourceListObject_t *res_list_obj = new ResourceListObject_t();
    res_list_obj->initialized = true;
    // If endpoint name not null, strip 'd/'
    if (endpoint_name) {
        res_list_obj->uri = res->uri_path() + 2;
    }
    tr_debug("Add resource %s to resource list!", res_list_obj->uri);
    res_list_obj->resource = res;
    res_list_obj->connection = connection;
    res_list_obj->acp = acp;

    client_data->resource_list.push_back(res_list_obj);

    return true;
}

EDGE_LOCAL void edgeclient_handle_async_coap_request_cb(const M2MBase &base,
                                                        M2MBase::Operation operation,
                                                        const uint8_t *token,
                                                        const uint8_t token_len,
                                                        const uint8_t *buffer,
                                                        size_t buffer_size,
                                                        void *client_args)
{
    tr_debug("edgeclient_handle_async_coap_request_cb: operation: %d, uri: %s, payload_size=%d, "
             "token_len=%d",
             operation,
             base.uri_path(),
             (int32_t) buffer_size,
             (int32_t) token_len);
    edge_rc_status_e rc_status;
    AsyncCallbackParamsBase *acp = (AsyncCallbackParamsBase *) client_args;
    M2MBase::BaseType type = base.base_type();
    if (type == M2MBase::Resource) {
        M2MResource *resource = (M2MResource *) &base;
        if (resource->operation() & operation) {
            if ((operation == M2MBase::PUT_ALLOWED) || (operation == M2MBase::POST_ALLOWED)) {
                uint8_t *copied_token = (uint8_t *) malloc(token_len);
                memcpy(copied_token, token, token_len);
                uint8_t *copied_buffer = (uint8_t *) malloc(buffer_size);
                memcpy(copied_buffer, buffer, buffer_size);
                if (!acp->async_request(resource,
                                        operation,
                                        copied_buffer,
                                        buffer_size,
                                        copied_token,
                                        token_len,
                                        &rc_status)) {
                    // Clean up, because handling the request failed for example, because it could not allocate memory.
                    M2MBase *base_ptr = (M2MBase *) &base;
                    tr_err("Async request couldn't be handled.");
                    coap_response_code_e coap_response_code;
                    switch (rc_status) {
                        case EDGE_RC_STATUS_INVALID_VALUE_FORMAT:
                            coap_response_code = COAP_RESPONSE_BAD_REQUEST;
                            break;
                        default:
                            coap_response_code = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
                            break;
                    }

                    (void) base_ptr->send_async_response_with_code(NULL, 0, token, token_len, coap_response_code);
                }
            } else if (M2MBase::GET_ALLOWED == operation) {
                // We can receive asynchronous get request to resource. In this case we respond immediately.
                uint8_t *value = NULL;
                uint32_t value_len = 0;
                resource->get_value(value, value_len);

                (void) resource->send_async_response_with_code(value,
                                                               value_len,
                                                               token,
                                                               token_len,
                                                               COAP_RESPONSE_CONTENT);
                free(value);
            }
        } else {
            tr_err("Operation %d is not allowed", operation);
            (void) resource->send_async_response_with_code(NULL, 0, token, token_len, COAP_RESPONSE_METHOD_NOT_ALLOWED);
        }
    } else {
        tr_err("Asynchronous CoAP request for non-resource type: %d", type);
        M2MBase *base_ptr = (M2MBase *) &base;
        (void) base_ptr->send_async_response_with_code(NULL, 0, token, token_len, COAP_RESPONSE_INTERNAL_SERVER_ERROR);
    }
}

pt_api_result_code_e edgeclient_send_asynchronous_response(const char *endpoint_name,
                                                           const uint16_t object_id,
                                                           const uint16_t object_instance_id,
                                                           const uint16_t resource_id,
                                                           uint8_t *token,
                                                           uint8_t token_len,
                                                           coap_response_code_e code)
{
    pt_api_result_code_e result = PT_API_SUCCESS;
    M2MResource *resource = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (resource) {
        AsyncCallbackParamsBase *acp = NULL;
        M2MCallbackAssociation *association = M2MCallbackStorage::
                get_association_item(*resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
        if (association) {
            acp = (AsyncCallbackParamsBase *) (association->_client_args);
        }
        if (acp) {
            tr_debug("Sending asynchronous response - token_len=%d", token_len);
            uint8_t *value = NULL;
            uint32_t value_len = 0;
            if (resource->operation() & M2MBase::POST_ALLOWED) {
                resource->get_value(value, value_len);
            }
            bool resource_success = resource->send_async_response_with_code(value, value_len, token, token_len, code);
            free(value);
            if (!resource_success) {
                result = PT_API_INTERNAL_ERROR;
            }
        } else {
            tr_err("Can't find async callback params for d/%s/%d/%d/%d !",
                   endpoint_name,
                   object_id,
                   object_instance_id,
                   resource_id);
            result = PT_API_INTERNAL_ERROR;
        }
    } else {
        tr_err("edgeclient_send_asynchronous_response - resource wasn't found for d/%s/%d/%d/%d !",
               endpoint_name,
               object_id,
               object_instance_id,
               resource_id);
        result = PT_API_RESOURCE_NOT_FOUND;
    }
    return result;
}

bool edgeclient_create_resource_structure(const char *endpoint_name,
                                          const uint16_t object_id,
                                          const uint16_t object_instance_id,
                                          const uint16_t resource_id,
                                          Lwm2mResourceType resource_type,
                                          int opr,
                                          void *ctx)
{
    M2MEndpoint *endpoint = NULL;
    M2MObject *object = NULL;
    M2MObjectInstance *instance = NULL;
    M2MResource *resource = NULL;

    if (endpoint_name == NULL) {
        tr_debug("create_resource_structure - %d/%d/%d", object_id, object_instance_id, resource_id);
    }
    else {
        tr_debug("create_resource_structure - d/%s/%d/%d/%d",
                 endpoint_name,
                 object_id,
                 object_instance_id,
                 resource_id);
    }

    resource = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    instance = edgeclient_get_object_instance(endpoint_name, object_id, object_instance_id);
    object = edgeclient_get_object(endpoint_name, object_id);
    endpoint = edgeclient_get_endpoint(endpoint_name);

    // Create endpoint if necessary
    if (endpoint_name != NULL && endpoint == NULL) {
        tr_debug("create_resource_structure - endpoint didn't exist yet,creating");
        if (!edgeclient_add_endpoint(endpoint_name, ctx)) {
            tr_error("create_resource_structure - could not create endpoint! (name=%s)", endpoint_name);
            return false;
        }
    }

    // Create object if necessary
    if (object == NULL) {
        tr_debug("create_resource_structure - object didn't exist yet,creating");
        if (!edgeclient_add_object(endpoint_name, object_id)) {
            tr_error("create_resource_structure - could not create object!");
            return false;
        }
    }

    // Create object instance if necessary
    if (instance == NULL) {
        tr_debug("create_resource_structure - object_instance didn't exist yet,creating");
        if (!edgeclient_add_object_instance(endpoint_name, object_id, object_instance_id)) {
            tr_error("create_resource_structure - could not create object instance!");
            return false;
        }
    }

    // Create resource if necessary
    if (resource == NULL) {
        tr_debug("create_resource_structure - resource didn't exist yet,creating");
        if (!edgeclient_add_resource(endpoint_name,
                                     object_id,
                                     object_instance_id,
                                     resource_id,
                                     resource_type,
                                     opr,
                                     ctx)) {
            tr_error("create_resource_structure - could not create resource!");
            return false;
        }
    }

    tr_debug("create_resource_structure - success");
    return true;
}

bool edgeclient_get_resource_attributes(const char *endpoint_name,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id,
                                        edgeclient_resource_attributes_t *attributes)
{
    M2MResource *res = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (res == NULL) {
        return false;
    }
    attributes->type = resolve_m2mresource_type(res->resource_instance_type());
    attributes->operations_allowed = res->operation();
    return true;
}

bool edgeclient_verify_value(const uint8_t *value, const uint32_t value_length, Lwm2mResourceType resource_type)
{
    if (value != NULL && value_length > 0) {
        size_t text_format_length = value_to_text_format(resource_type, value, value_length, NULL);
        if (text_format_length == 0) {
            return false;
        }
    }
    return true;
}

bool edgeclient_get_endpoint_context(const char *endpoint_name, void **context_out)
{
    M2MEndpoint *endpoint = edgeclient_get_endpoint(endpoint_name);
    if (endpoint && !endpoint->is_deleted()) {
        *context_out = endpoint->get_context();
        return true;
    }
    *context_out = NULL;
    return false;
}

pt_api_result_code_e edgeclient_update_resource_value(const char *endpoint_name,
                                                      const uint16_t object_id,
                                                      const uint16_t object_instance_id,
                                                      const uint16_t resource_id,
                                                      const uint8_t *value,
                                                      uint32_t value_length)
{
    M2MResource *res = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (res == NULL) {
        return PT_API_RESOURCE_NOT_FOUND;
    }
    Lwm2mResourceType resource_type = resolve_m2mresource_type(res->resource_instance_type());
    bool value_ok = edgeclient_verify_value(value, value_length, resource_type);
    if (!value_ok) {
        return PT_API_ILLEGAL_VALUE;
    }
    if (!(res->operation() & OPERATION_WRITE)) {
        return PT_API_RESOURCE_NOT_WRITABLE;
    }
    char *text_format;
    size_t text_format_length = value_to_text_format(resource_type, value, value_length, &text_format);
    if (text_format_length > 0 && text_format != NULL) {
        res->update_value((uint8_t *) text_format, text_format_length);
    } else {
        return PT_API_INTERNAL_ERROR;
    }
    return PT_API_SUCCESS;
}

pt_api_result_code_e edgeclient_set_resource_value(const char *endpoint_name, const uint16_t object_id,
                                                   const uint16_t object_instance_id, const uint16_t resource_id,
                                                   const uint8_t *value, const uint32_t value_length,
                                                   Lwm2mResourceType resource_type, int opr, void *ctx)
{
    if (!edgeclient_create_resource_structure(endpoint_name,
                                              object_id,
                                              object_instance_id,
                                              resource_id,
                                              resource_type,
                                              opr,
                                              ctx)) {
        tr_error("set_endpoint_resource_value - could not create resource structure!");
        return PT_API_INTERNAL_ERROR;
    }
    M2MResource *res = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (res == NULL) {
        return PT_API_INTERNAL_ERROR;
    }
    if (value != NULL && value_length > 0) {
        char* text_format = NULL;
        size_t text_format_length = value_to_text_format(resource_type, value, value_length, &text_format);
        if (text_format_length > 0 && text_format != NULL) {
            res->update_value((uint8_t*) text_format, text_format_length);
        } else {
            return PT_API_ILLEGAL_VALUE;
        }
    }
    return PT_API_SUCCESS;
}

bool edgeclient_get_resource_value_and_attributes(const char *endpoint_name,
                                                  const uint16_t object_id,
                                                  const uint16_t object_instance_id,
                                                  const uint16_t resource_id,
                                                  uint8_t **value_out,
                                                  uint32_t *value_length_out,
                                                  edgeclient_resource_attributes_t *attributes)
{
    if (value_out == NULL || value_length_out == NULL) {
        return false;
    }
    M2MResource *res = edgelient_get_resource(endpoint_name, object_id, object_instance_id, resource_id);
    if (res == NULL) {
        return false;
    }
    res->get_value(*value_out, *value_length_out);
    if (attributes) {
        attributes->type = resolve_m2mresource_type(res->resource_instance_type());
        attributes->operations_allowed = res->operation();
    }
    return true;
}

bool edgeclient_get_resource_value(const char *endpoint_name,
                                   const uint16_t object_id,
                                   const uint16_t object_instance_id,
                                   const uint16_t resource_id,
                                   uint8_t **value_out,
                                   uint32_t *value_length_out)
{
    return edgeclient_get_resource_value_and_attributes(endpoint_name,
                                                        object_id,
                                                        object_instance_id,
                                                        resource_id,
                                                        value_out,
                                                        value_length_out,
                                                        NULL);
}

EDGE_LOCAL void create_root_folder(pal_fsStorageID_t partition_id, const char *folder_path)
{
    // Make the sub-folder
    palStatus_t res = pal_fsMkDir(folder_path);

    if (res == PAL_ERR_FS_NAME_ALREADY_EXIST) {
        tr_debug("'%s' folder already exists when checking partition id %d", folder_path, partition_id);
    } else if (res == PAL_SUCCESS) {
        tr_debug("Created '%s' folder for partition %d.", folder_path, partition_id);
    } else {
        tr_err("'%s' cannot be created for partition %d - reason '%d'", folder_path, partition_id, res);
    }
}

EDGE_LOCAL void setup_config_mountdir()
{
#define NUM_PATHS 2
    pal_fsStorageID_t partitions[NUM_PATHS] = {PAL_FS_PARTITION_PRIMARY, PAL_FS_PARTITION_SECONDARY};
    const char *paths[NUM_PATHS] = {PAL_FS_MOUNT_POINT_PRIMARY, PAL_FS_MOUNT_POINT_SECONDARY};
    int32_t path_index;

    for (path_index = 0; path_index < NUM_PATHS; path_index++) {
        pal_fsStorageID_t data_id = partitions[path_index];
        create_root_folder(data_id, paths[path_index]);
        if (pal_fsSetMountPoint(data_id, paths[path_index]) != PAL_SUCCESS) {
            tr_error("setup_config_mountdir: - can't set fsSetMountPoint to PAL (%d, %s)\n",
                     (int) data_id,
                     paths[path_index]);
            exit(1);
        }
    }
}

EDGE_LOCAL void edgeclient_setup_credentials(bool reset_storage, byoc_data_t *byoc_data)
{
    fcc_status_e status = fcc_init();
    if (status != FCC_STATUS_SUCCESS) {
        tr_error("fcc_init failed with status %d!", status);
        exit(1);
    }

    if (reset_storage) {
        tr_info("Resets storage to an empty state");
        fcc_status_e delete_status = fcc_storage_delete();
        if (delete_status != FCC_STATUS_SUCCESS) {
            tr_error("Failed to delete storage - %d", delete_status);
            exit(1);
        }
    }

#if BYOC_MODE
    tr_info("Starting in BYOC mode.");
    status = fcc_verify_device_configured_4mbed_cloud();
    tr_debug("fcc_verify_device_configured_4mbed_cloud  = %d", status);
    tr_debug("reset_storage  = %d", reset_storage);
    if (reset_storage || status != FCC_STATUS_SUCCESS) {
        edgeclient_inject_byoc(byoc_data);
    } else {
        if(byoc_data->cbor_file && status == FCC_STATUS_SUCCESS) {
            mbed_tracef(TRACE_LEVEL_WARN, TRACE_GROUP, "%s", "KCM seems to exist already. \
                                                              You need to use --reset-storage \
                                                              to override it. Now continuing with old identity.");
        }
    }
#elif defined(DEVELOPER_MODE)
    tr_info("Starting in DEVELOPER mode.");
    tr_info("Injecting developer certificate injection");
    status = fcc_developer_flow();
    tr_debug("fcc_bootstrap_flow status %d", status);
    if (status == FCC_STATUS_KCM_FILE_EXIST_ERROR) {
        tr_warn("KCM data already exits");
    } else if (status != FCC_STATUS_SUCCESS) {
        tr_error("Failed to load certificate credentials - exit");
    }
#endif
    edgeclient_destroy_byoc_data(byoc_data);
    status = fcc_verify_device_configured_4mbed_cloud();
    if (status != FCC_STATUS_SUCCESS) {
        tr_error("Device not configured for Device Management - exit");
        exit(1);
    }
}

/*
 * Static helper functions for manipulating cloud-client's c++ objects etc. below
 */

EDGE_LOCAL void edgeclient_add_client_objects_for_registering()
{
    // Move pending objects to registering list to be registered
    M2MBaseList::iterator it;
    for (it = client_data->pending_objects.begin(); it != client_data->pending_objects.end(); it++) {
        client_data->registering_objects.push_back(*it);
        edgeclient_set_update_register_needed();
    }
    // Clear objects from pending list
    client_data->pending_objects.clear();

    // Remove objects flagged to be deleted, those shall not be handed to client.
    M2MBaseList list;
    for (it = client_data->registering_objects.begin(); it != client_data->registering_objects.end(); it++) {
        const char* name = (*it)->name();
        tr_debug("edgeclient_add_client_objects_for_registering: checking if object in index %s is deleted.", name);
        if (!(*it)->is_deleted()) {
            tr_debug("edgeclient_add_client_objects_for_registering: object in %s is not deleted.", name);
            list.push_back(*it);
        }
    }

    // Give new objects to client
    client->add_objects(list);
}

EDGE_LOCAL M2MEndpoint *edgeclient_find_endpoint_from_list(
    const char *endpoint_name, M2MBaseList &list, M2MBaseList **found_list, int *found_index)
{
    M2MEndpoint *match = NULL;
    M2MBaseList::iterator it;
    int index;

    if (found_index) {
        *found_index = -1;
    }
    if (found_list) {
        *found_list = NULL;
    }

    for (it = list.begin(),index=0; it != list.end(); it++, index++) {
        if ((*it)->base_type() == M2MBase::ObjectDirectory) {
            if (strcmp((*it)->name(), endpoint_name) == 0) {
                match = (M2MEndpoint*)*it;
                if (found_index) {
                    *found_index = index;
                }
                if (found_list) {
                    *found_list = &list;
                }
                break;
            }
        }
    }
    return match;
}

EDGE_LOCAL M2MObject *edgeclient_find_object_from_list(const uint16_t object_id,
                                                       M2MBaseList &list,
                                                       M2MBaseList **found_list,
                                                       int *found_index)
{
    M2MObject *match = NULL;
    M2MBaseList::iterator it;
    int index;

    if (found_index) {
        *found_index = -1;
    }
    if (found_list) {
        *found_list = NULL;
    }

    for (it = list.begin(),index=0; it != list.end(); it++, index++) {
        if ((*it)->base_type() == M2MBase::Object) {
            if ((*it)->name_id() == object_id) {
                match = (M2MObject*)*it;
                if (found_index) {
                    *found_index = index;
                }
                if (found_list) {
                    *found_list = &list;
                }
                break;
            }
        }
    }
    return match;
}
EDGE_LOCAL M2MEndpoint *edgeclient_get_endpoint_with_index(const char *endpoint_name,
                                                           M2MBaseList **found_list,
                                                           int *found_index)
{
    if (endpoint_name == NULL) {
        return NULL;
    }
    M2MEndpoint *match = edgeclient_find_endpoint_from_list(endpoint_name,
                                                            client_data->registered_objects,
                                                            found_list,
                                                            found_index);
    if (match == NULL) {
        match = edgeclient_find_endpoint_from_list(endpoint_name,
                                                   client_data->pending_objects,
                                                   found_list,
                                                   found_index);
    }
    if (match == NULL) {
        match = edgeclient_find_endpoint_from_list(endpoint_name,
                                                   client_data->registering_objects,
                                                   found_list,
                                                   found_index);
    }
    return match;
}

EDGE_LOCAL M2MObject *edgeclient_get_object_with_index(const uint16_t object_id,
                                                       M2MBaseList **found_list,
                                                       int *found_index)
{
    M2MObject *match = edgeclient_find_object_from_list(object_id,
                                                        client_data->registered_objects,
                                                        found_list,
                                                        found_index);
    if (match == NULL) {
        match = edgeclient_find_object_from_list(object_id, client_data->pending_objects, found_list, found_index);
    }
    if (match == NULL) {
        match = edgeclient_find_object_from_list(object_id, client_data->registering_objects, found_list, found_index);
    }
    return match;
}

EDGE_LOCAL M2MEndpoint *edgeclient_get_endpoint(const char *endpoint_name)
{
    return edgeclient_get_endpoint_with_index(endpoint_name, NULL, NULL);
}

EDGE_LOCAL M2MObject *edgeclient_get_object(const char *endpoint_name, const uint16_t object_id) {
    M2MEndpoint *ep = NULL;
    M2MObject *match = NULL;
    char object_name[6];
    if (endpoint_name != NULL) {
        tr_debug("get_object - endpoint");
        // Get the object from endpoint with given name
        ep = edgeclient_get_endpoint(endpoint_name);
        if (ep == NULL) {
            return NULL;
        }
        uint32_t size = m2m::itoa_c(object_id, object_name);
        match = ep->object(String(object_name, size));
    }
    else {
        tr_debug("get_object - root");
        // Get the object from Edge Core
        match = edgeclient_get_object_with_index(object_id, NULL, NULL);
    }
    return match;
}

EDGE_LOCAL M2MObjectInstance *edgeclient_get_object_instance(const char *endpoint_name,
                                                             const uint16_t object_id,
                                                             const uint16_t object_instance_id)
{
    M2MObject *obj = edgeclient_get_object(endpoint_name, object_id);
    if (obj == NULL) {
        return NULL;
    }
    return obj->object_instance(object_instance_id);
}

EDGE_LOCAL M2MResource *edgelient_get_resource(const char *endpoint_name,
                                               const uint16_t object_id,
                                               const uint16_t object_instance_id,
                                               const uint16_t resource_id)
{
    M2MObjectInstance *obj_inst = edgeclient_get_object_instance(endpoint_name, object_id, object_instance_id);
    if (obj_inst == NULL) {
        return NULL;
    }
    char res_name[6] = {0};
    m2m::itoa_c(resource_id, res_name);
    return obj_inst->resource(res_name);
}

EDGE_LOCAL bool edgeclient_is_registration_needed()
{
    bool ret;
    ret = client_data->m2m_resources_added_or_removed;
    tr_debug("< is_registration_needed %d", ret);
    return ret;
}

EDGE_LOCAL void edgeclient_set_update_register_needed()
{
    tr_debug("set_update_register_client_needed");
    client_data->m2m_resources_added_or_removed = true;
}

int edgeclient_write_to_pt_cb(edgeclient_request_context_t *request_ctx, void *ctx)
{
    return client_data->g_handle_write_to_pt_cb(request_ctx, ctx);
}

const char* edgeclient_get_internal_id()
{
    return client->get_internal_id();
}

const char* edgeclient_get_account_id()
{
    return client->get_account_id();
}

const char* edgeclient_get_lwm2m_server_uri()
{
    return client->get_lwm2m_server_uri();
}

const char* edgeclient_get_endpoint_name()
{
    return client->get_endpoint_name();
}

bool edgeclient_is_shutting_down()
{
    return client->is_interrupt_received();
}

/*
 * Edge management data functions
 */

void edgeclient_destroy_device_list(edge_device_list_t *devices)
{
    ns_list_foreach_safe(edge_device_entry_t, device, devices) {
        ns_list_foreach_safe(edge_device_resource_entry_t, resource, device->resources) {
            ns_list_remove(device->resources, resource);
            free(resource->uri);
            free(resource);
        }
        ns_list_remove(devices, device);
        free(device->resources);
        free(device->name);
        free(device);
    }
    free(devices);
}

edge_device_list_t *edgeclient_devices()
{
    edge_device_list_t *devices = (edge_device_list_t*) malloc(sizeof(edge_device_list_t));
    if (!devices) {
        tr_err("Could not allocate devices list.");
        return NULL;
    }
    ns_list_init(devices);

    const M2MBaseList *objects = client->get_object_list();
    if (!objects) {
        return devices;
    }

    M2MBaseList::const_iterator it = objects->begin();
    for (; it != objects->end(); it++) {
        if ((*it)->base_type() == M2MBase::ObjectDirectory) {
            M2MEndpoint *endpoint = (M2MEndpoint*)*it;

            // Skip deleted endpoints
            if (endpoint->is_deleted()) continue;

            edge_device_entry_t *entry = (edge_device_entry_t*) malloc(sizeof(edge_device_entry_t));
            edge_device_resource_list_t *resources = (edge_device_resource_list_t*) malloc(sizeof(edge_device_resource_list_t));
            char *name = strdup(endpoint->name());

            if (!entry || !resources || !name) {
                free(entry);
                free(resources);
                free(name);
                tr_err("Could not allocate device entry for device listing.");
                // Destroy the possibly created device list content.
                goto clean_device_list;
            }

            ns_list_init(resources);
            entry->resources = resources;
            entry->name = name;
            ns_list_add_to_end(devices, entry);

            M2MObjectList objects = endpoint->objects();
            if (objects.empty()) {
                continue;
            }

            M2MObjectList::const_iterator obj_it = objects.begin();
            M2MObjectInstanceList::const_iterator ins_it;
            M2MResourceList::const_iterator res_it;
            for (; obj_it != objects.end(); obj_it++) {
                M2MObject *obj = (M2MObject*)*obj_it;
                M2MObjectInstanceList instances = obj->instances();

                if (instances.empty()) {
                    continue;
                }

                for (ins_it = instances.begin(); ins_it != instances.end(); ins_it++) {
                    M2MObjectInstance *ins = (M2MObjectInstance*)*ins_it;
                    M2MResourceList resources = ins->resources();

                    if (resources.empty()) {
                        continue;
                    }

                    for (res_it = resources.begin(); res_it != resources.end(); res_it++) {
                        M2MResource *res = (M2MResource*)*res_it;
                        edge_device_resource_entry_t *resource_entry = (edge_device_resource_entry_t*) malloc(sizeof(edge_device_resource_entry_t));

                        if (!resource_entry) {
                            tr_err("Could not allocate resource entry for device listing.");
                            goto clean_device_list;
                        }

                        char uri[64];
                        // Device Management Client stores the identifier as string for
                        // object and resource. The object instance has uint16_t as identifier.
                        sprintf(uri, "/%s/%d/%s", obj->name(), ins->instance_id(), res->name());
                        resource_entry->uri = strdup(uri);
                        Lwm2mResourceType resource_type = resolve_m2mresource_type(res->resource_instance_type());
                        resource_entry->type = resource_type;
                        resource_entry->operation = res->operation();
                        ns_list_add_to_end(entry->resources, resource_entry);
                    }
                }
            }
        }
    }

    return devices;
clean_device_list:
    tr_err("Device list request failed.");
    if (devices) {
        edgeclient_destroy_device_list(devices);
    }
    return NULL;
}

EDGE_LOCAL void edgeclient_on_est_status_callback(est_enrollment_result_e result,
                                                  struct cert_chain_context_s *cert_chain,
                                                  void *context)
{
    int ret_val = client_data->g_handle_est_status_cb(result, cert_chain, context);
    client->est_free_cert_chain_context(cert_chain);
    (void) ret_val;
}

pt_api_result_code_e edgeclient_request_est_enrollment(const char *certificate_name,
                                       uint8_t *csr,
                                       const size_t csr_length,
                                       void *context)
{
    est_status_e est_status = client->est_request_enrollment(certificate_name, csr, csr_length, context);
    if (est_status == EST_STATUS_SUCCESS) {
        return PT_API_SUCCESS;
    }
    else if (est_status == EST_STATUS_INVALID_PARAMETERS) {
        return PT_API_CERTIFICATE_RENEWAL_INVALID_PARAMETERS;
    }
    else if (est_status == EST_STATUS_MEMORY_ALLOCATION_FAILURE) {
        return PT_API_CERTIFICATE_RENEWAL_MEMORY_ALLOCATION_FAILURE;
    }
    return PT_API_INTERNAL_ERROR;
}
