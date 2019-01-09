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

#ifndef EDGE_CLIENT_INTERNAL_H_
#define EDGE_CLIENT_INTERNAL_H_
#include "common/test_support.h"
#include "m2mbase.h"
#include "m2minterface.h"
#include "common/edge_mutex.h"
#include "m2mresourceinstance.h"
#include "edge-client/edge_client.h"
#include "edge-client/execute_cb_params_base.h"
#include "edge-client/edge_client_byoc.h"
#include <event2/event.h>

typedef struct {
    bool initialized;
    const char* uri;
    void *connection; // used to identify which Protocol API this resource belongs to.
    M2MResource* resource;
    ExecuteCallbackParamsBase *ecp;
} ResourceListObject_t;

typedef enum {
    UNREGISTERED,
    REGISTERING,
    REGISTERED,
    ERROR
} edgeClientStatus_e;

typedef struct edgeclient_data_s {
    edgeclient_data_s() : m2m_resources_added_or_removed(false),
                          g_handle_write_to_pt_cb(NULL),
                          g_handle_register_cb(NULL),
                          g_handle_unregister_cb(NULL),
                          g_handle_error_cb(NULL),
                          edgeclient_status(UNREGISTERED)
    {
    }
    virtual ~edgeclient_data_s();
    M2MBaseList pending_objects; /**< Objects pending for registration or deregistration */
    M2MBaseList registering_objects; /**< Objects in registration phase. */
    M2MBaseList registered_objects; /**< Registered objects.  */
    bool m2m_resources_added_or_removed;


    Vector<ResourceListObject_t*> resource_list;

    handle_write_to_pt_cb g_handle_write_to_pt_cb;
    handle_register_cb g_handle_register_cb;
    handle_unregister_cb g_handle_unregister_cb;
    handle_error_cb g_handle_error_cb;
    volatile edgeClientStatus_e edgeclient_status;
} edgeclient_data_t;

#ifdef BUILD_TYPE_TEST
extern edge_mutex_t edgeclient_mutex;
class EdgeClientImpl;
extern EdgeClientImpl *client;

/**
 * \brief This function converts the byte data based on the resource type to text.
 *
 * This function expects to get in LWM2M resource value in:
 *        For different LWM2M data types there are byte-order restrictions:
 *        String: UTF-8
 *        Integer: binary signed integer in network byte-order (8, 16, 32 or 64 bits).
 *        Float: IEEE 754-2008 floating point value in network byte-order (32 or 64 bits).
 *        Boolean: 8 bit unsigned integer with value 0 or 1.
 *        Opaque: sequence of binary data.
 *        Time: Same representation as Integer.
 *        Objlnk: Two 16 bit unsigned integers one beside the other.
 *                First is the Object ID and second is the Object Instance ID.
 *
 *        Refer to: OMA Lightweight Machine to Machine Technical Specification
 *        for data type specifications.
 *
 * The output of the conversion to text format is also defined in the same specification.
 *
 * \param resource_type The resource value data type.
 * \param value The pointer to data buffer. Ownership of the value is in the calling function.
 * \param value_length The size of the data.
 * \param buffer The pointer where to pass the formatted value.
 *               The memory for the buffer is allocated in this function but the ownership
 *               of the buffer is in the calling function.
 * \return The size of the formatted data. If size is 0 the value could not be formatted.
 */
size_t value_to_text_format(Lwm2mResourceType resource_type, const uint8_t* value, const uint32_t value_length, char** buffer);

#endif

extern edgeclient_data_t *client_data;
EDGE_LOCAL void edgeclient_update_register_msg_cb(void *arg);
EDGE_LOCAL void edgeclient_on_unregistered_callback(void);
EDGE_LOCAL void edgeclient_on_registered_callback(void);
EDGE_LOCAL void edgeclient_set_update_register_needed(edgeclient_mutex_action_e mutex_action);
EDGE_LOCAL bool edgeclient_is_registration_needed();
EDGE_LOCAL void edgeclient_setup_credentials(bool reset_storage, byoc_data_t *byoc_data);
EDGE_LOCAL M2MEndpoint *edgeclient_get_endpoint_with_index(const char *endpoint_name, M2MBaseList **found_list, int *found_index);
EDGE_LOCAL M2MEndpoint *edgeclient_get_endpoint(const char *endpoint_name);
EDGE_LOCAL M2MObject *edgeclient_get_object(const char *endpoint_name, const uint16_t object_id);
EDGE_LOCAL M2MObjectInstance *edgeclient_get_object_instance(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id);
EDGE_LOCAL M2MResource *edgelient_get_resource(const char *endpoint_name, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id);
EDGE_LOCAL void edgeclient_add_client_objects_for_registering();
EDGE_LOCAL void edgeclient_endpoint_value_set_handler(const M2MResourceBase *resource_base,
                                                 uint8_t *value,
                                                 const uint32_t value_length);

#endif /* EDGE_CLIENT_INTERNAL_H_ */
