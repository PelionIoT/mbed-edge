#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "fcc_status.h"
#include "edge-client/edge_client.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mbase.h"
#include "m2minterfacefactory.h"
#include "edge-client/edge_client_internal.h"
#include "testfactory.h"
#include "cpputest-custom-types/value_pointer.h"
#include "test-lib/edgeclient_request_context.h"
#include "common/constants.h"
#include "include/m2mcallbackstorage.h"
#include "edge-client/edge_client_impl.h"
#include "edge-client/edge_core_cb.h"
#include "edge-client/reset_factory_settings_internal.h"
#include "edge-client/edge_client_cpp.h"
#include "edge-client/async_cb_params.h"
#include "test-lib/msg_api_test_helper.h"
extern "C" {
#include "edge-core/edge_device_object.h"
#include "edge-client/reset_factory_settings.h"
#include "kcm_status.h"
#include "edge-core/edge_server.h"
#include "test-lib/evbase_mock.h"
#include "common/apr_base64.h"
#include "common/msg_api.h"
#include "common/msg_api_internal.h"
}

#define N_TIMES(n, cmd) { \
    int32_t i; \
    for(i = 0; i < n; i++) { \
        cmd; \
    } \
}

#define to_str(s) to_s(s)
#define to_s(s) #s

#define TEST_CLIENT_CTX ((void *) (0x123))
#define TEST_CLIENT_CTX_2 ((void *) (0x124))
#define TEST_OBJECT_ID 100
#define TEST_OBJECT_INSTANCE_ID 1000
#define TEST_RESOURCE_ID 10000
#define TEST_RESOURCE_ID_2 10001
#define ENDPOINT_NAME "test"
#define EXECUTABLE_PATH "http://example.com/test.exe"

static M2MEndpoint *create_endpoint(String &name, char *path);
static M2MObject *create_object(String &object_id, char *path, bool external_blockwise_store);
static M2MObjectInstance *create_object_instance(M2MObject *parent);
static M2MResource *create_resource(M2MObjectInstance *parent, String &resource_name);
static void expect_find_endpoint_with_name(const char *name, M2MEndpoint *endpoint, void* ctx);
static void expect_endpoint_destructor(M2MEndpoint *endpoint);
static void expect_create_object(String &name, M2MObject *object);
void edgeclient_on_error_callback(int error_code, const char *error_description);
static void find_object_type_id_expectations(M2MObject *object, const char *object_id);
static void find_object_instance_expectations(M2MObject *object, M2MObjectInstance *object_instance, uint16_t inst_id);
static void find_resource_expectations(M2MObjectInstance *object_instance,
                                       String &resource_name,
                                       M2MResource *resource);
static void create_dynamic_resource_expectations(String &resource_id,
                                                 String &resource_type,
                                                 M2MResource *created_resource,
                                                 Lwm2mResourceType type);

class SetResourceParams {
 public:
    String *endpoint_name;
    char *value;
    const char *text_format_value;
    uint32_t text_format_value_length;
    uint32_t value_length;
    String object_id;
    Lwm2mResourceType value_type;
    uint16_t object_instance_id;
    String resource_id;
    const char *resource_type;
    M2MEndpoint *endpoint;
    M2MObject *object;
    M2MObjectInstance *object_instance;
    M2MResource *resource;
    M2MBase::Operation operation;
    void *ctx;

    SetResourceParams(const char *endpoint_name,
                      const char *object_id,
                      uint16_t object_instance_id,
                      const char *resource_id,
                      const char *resource_name,
                      const char *value,
                      uint32_t value_length,
                      const char *text_format_value,
                      M2MBase::Operation operation,
                      void *ctx = (void *) TEST_CLIENT_CTX,
                      Lwm2mResourceType resource_type = LWM2M_OPAQUE)
    {
        this->endpoint = NULL;
        this->endpoint_name = NULL;
        if (endpoint_name) {
            this->endpoint_name = new String(endpoint_name);
        }

        this->resource_type = NULL;
        if (resource_name) {
            this->resource_type = resource_name;
        }

        if (value) {
            this->value = (char*) malloc(strlen(value));
            memcpy(this->value, value, value_length);
            this->value_length = value_length;
        } else {
            this->value = NULL;
            this->value_length = 0;
        }
        this->text_format_value = text_format_value;
        this->text_format_value_length = 0;
        if (text_format_value) {
            this->text_format_value_length = strlen(text_format_value);
        }
        this->value_type = resource_type;
        this->object_id = String(object_id);
        this->object_instance_id = object_instance_id;
        this->resource_id = resource_id;
        this->operation = operation;
        char *path = (char *) malloc(100);
        if (endpoint_name) {
            strcpy(path, "d/");
            strcat(path, endpoint_name);
            strcat(path, "/");
        } else {
            strcpy(path, "");
        }
        object = create_object(this->object_id, path, false);
        object_instance = create_object_instance(object);
        resource = create_resource(this->object_instance, this->resource_id);
        this->ctx = ctx;
    }


    void set_integer_value(int32_t *int_value)
    {
        if (value) {
            free(value);
        }
        value_type = LWM2M_INTEGER;
        // Values must be in network byte order
        value = (char *) malloc(sizeof(int32_t));
        int32_t temp = htonl(*int_value);
        memcpy(value, &temp, sizeof(int32_t));
        value_length = sizeof(int32_t);
    }

    void set_float_value(float *float_value)
    {
        if (value) {
            free(value);
        }
        value_type = LWM2M_FLOAT;
        // Values must be in network byte order
        uint32_t temp = 0;
        memcpy(&temp, float_value, sizeof(float));
        temp = htonl(temp);
        value = (char *) malloc(sizeof(float));
        memcpy(value, &temp, sizeof(float));
        value_length = sizeof(float);
    }

    ~SetResourceParams()
    {
        mock().disable();
        TestFactory::delete_resource(resource);
        TestFactory::delete_object_instance(object_instance);
        TestFactory::delete_object(object);
        if (endpoint_name) {
            delete endpoint_name;
        }
        free(value);
        mock().enable();
    }
};

static void set_resource_value(SetResourceParams &params);

static int write_to_pt_dummy(edgeclient_request_context_t *request_ctx, void *userdata)
{
    EdgeClientRequestContext ctx(request_ctx->device_id,
                                 request_ctx->object_id,
                                 request_ctx->object_instance_id,
                                 request_ctx->resource_id,
                                 request_ctx->value,
                                 request_ctx->value_len,
                                 request_ctx->token,
                                 request_ctx->token_len,
                                 request_ctx->operation,
                                 (void *) request_ctx->success_handler,
                                 (void *) request_ctx->failure_handler,
                                 request_ctx->connection);
    int ret = mock()
        .actualCall("write_to_pt_dummy")
        .withParameterOfType("EdgeClientRequestContext", "request_ctx", (const void*) &ctx)
        .withPointerParameter("userdata", userdata)
        .returnIntValue();
    // Only deallocate it in case of success. Otherwise our implementation should deallocate it.
    if (0 == ret) {
        edgeclient_deallocate_request_context(request_ctx);
    }
    return ret;
}

static void register_dummy(void)
{
    mock().actualCall("register_dummy");
}

static void unregister_dummy(void)
{
    mock().actualCall("unregister_dummy");
}

static void error_dummy(int error_code, const char *error_description)
{
    mock().actualCall("error_dummy")
            .withIntParameter("error_code", error_code)
            .withStringParameter("error_description", error_description);
}

static int certificate_renewal_notifier_mock(const char *certificate_name,
                                             ce_status_e status,
                                             ce_initiator_e initiator,
                                             void *ctx)
{
    return mock()
            .actualCall("certificate_renewal_notifier_mock")
            .withStringParameter("name", certificate_name)
            .withIntParameter("status", status)
            .withIntParameter("initiator", initiator)
            .withPointerParameter("ctx", ctx)
            .returnIntValue();
}

static void set_default_create_params(edgeclient_create_parameters_t *params)
{
    memset(params, 0, sizeof(edgeclient_create_parameters_t));
    params->handle_write_to_pt_cb = write_to_pt_dummy;
    params->handle_register_cb = register_dummy;
    params->handle_unregister_cb = unregister_dummy;
    params->handle_error_cb = error_dummy;
    params->handle_cert_renewal_status_cb = certificate_renewal_notifier_mock;
    params->cert_renewal_ctx = (void *) 0x123;
}

TEST_GROUP(edge_client_precheck) {
    void setup()
    {
    }

    void teardown()
    {
    }
};


TEST_GROUP(edge_client) {
    void setup()
    {
        mock().disable();
        edgeclient_create_parameters_t params;
        // This shall not leak, after setting credentials Edge will free.
        byoc_data_t *dummy_byoc = (byoc_data_t*) malloc(sizeof(byoc_data_t));
        dummy_byoc->cbor_file = "/dummy/byoc";
        set_default_create_params(&params);
        params.reset_storage = true;
        edgeclient_create(&params, dummy_byoc);
        edgeclient_connect();
        mock().enable();
    }

    void teardown()
    {
        mock().disable();
        edgeclient_destroy();
        M2MCallbackStorage::delete_instance();
        mock().enable();
    }
};

static void connect_expectations(int32_t registering_objects_count)
{
    int32_t i;

    mock().expectOneCall("MbedCloudClient::add_objects");
    for (i = 0; i < registering_objects_count; i++) {
        mock().expectOneCall("MbedCloudClient::add_object_stub");
    }
}

static void create_expectations(bool storage_delete, fcc_status_e fccStatus)
{
    mock().strictOrder();
    mock().expectOneCall("pal_fsMkDir")
            .withStringParameter("pathName", "./mcc_config")
            .andReturnValue(PAL_SUCCESS);
    mock().expectOneCall("pal_fsSetMountPoint")
            .withStringParameter("Path", "./mcc_config")
            .withIntParameter("dataID", (int32_t) PAL_FS_PARTITION_PRIMARY)
            .andReturnValue(PAL_SUCCESS);
    mock().expectOneCall("pal_fsMkDir")
            .withStringParameter("pathName", "./mcc_config")
            .andReturnValue(PAL_ERR_FS_NAME_ALREADY_EXIST);
    mock().expectOneCall("pal_fsSetMountPoint")
            .withStringParameter("Path", "./mcc_config")
            .withIntParameter("dataID", (int32_t) PAL_FS_PARTITION_SECONDARY)
            .andReturnValue(PAL_SUCCESS);
    mock().expectOneCall("fcc_init");

    if (storage_delete) {
        mock().expectOneCall("fcc_storage_delete").andReturnValue(FCC_STATUS_SUCCESS);
    }

#if BYOC_MODE
    mock().expectOneCall("fcc_verify_device_configured_4mbed_cloud").andReturnValue(fccStatus);
    mock().expectOneCall("edge_read_file").andReturnValue(0);
    mock().expectOneCall("fcc_storage_delete").andReturnValue(FCC_STATUS_SUCCESS);
    mock().expectOneCall("fcc_bundle_handler").andReturnValue(FCC_STATUS_SUCCESS);
#endif
    mock().expectOneCall("fcc_verify_device_configured_4mbed_cloud").andReturnValue(FCC_STATUS_SUCCESS);
    mock().expectOneCall("MbedCloudClient::MbedCloudClient");
    mock().expectOneCall("MbedCloudClient::set_update_callback");
    mock().expectOneCall("MbedCloudClient::on_certificate_renewal").ignoreOtherParameters();
}


static void destroy_expectations()
{
    mock().expectOneCall("MbedCloudClient::~MbedCloudClient");
    mock().expectOneCall("fcc_finalize");
    mock().expectOneCall("ns_event_loop_thread_stop");
}

TEST(edge_client_precheck, test_create_and_connect_client)
{
    printf("test_create_and_connect_client");
    create_expectations(false, FCC_STATUS_NOT_INITIALIZED);
    edgeclient_create_parameters_t params;
    byoc_data_t *dummy_byoc = (byoc_data_t*) malloc(sizeof(byoc_data_t));
    dummy_byoc->cbor_file = "/dummy/byoc";
    set_default_create_params(&params);
    params.reset_storage = false;
    edgeclient_create(&params, dummy_byoc);
    connect_expectations(0);
    edgeclient_connect();
    destroy_expectations();
    edgeclient_destroy();

    mock().checkExpectations();
}

TEST(edge_client_precheck, test_create_and_connect_client_resetting_storage)
{
    printf("test_create_and_connect_client_resetting_storage");
    create_expectations(true, FCC_STATUS_SUCCESS);
    edgeclient_create_parameters_t params;
    byoc_data_t *dummy_byoc = (byoc_data_t*) malloc(sizeof(byoc_data_t));
    dummy_byoc->cbor_file = "/dummy/byoc";
    set_default_create_params(&params);
    params.reset_storage = true;
    edgeclient_create(&params, dummy_byoc);
    connect_expectations(0);
    edgeclient_connect();
    destroy_expectations();
    edgeclient_destroy();

    mock().checkExpectations();
}

static void on_registered_expectations(struct event_base *base)
{
    expect_event_message(base, edgeclient_on_registered_callback_safe, true /* succeeds */);
}

TEST(edge_client, test_edge_client_on_registered_callback_when_send_message_fails)
{
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, edgeclient_on_registered_callback_safe, false /* succeeds */);

    edgeclient_on_registered_callback();
    evbase_mock_delete(base);
}

static void on_registered_safe_expectations(struct event_base *base,
                                            SetResourceParams *params,
                                            bool add_objects_after_update_register_call,
                                            bool interrupt_received)
{
    if (params) {
        M2MBase::BaseType type = M2MBase::ObjectDirectory;
        mock().expectOneCall("M2MBase::base_type")
                .withPointerParameter("this", (void *) params->endpoint)
                .andReturnValue((int) type);
        mock().expectOneCall("M2MEndpoint::is_deleted").andReturnValue(false);
    }
    mock().expectOneCall("register_dummy");
    if (interrupt_received && !add_objects_after_update_register_call) {
        mock().expectOneCall("edgeserver_graceful_shutdown");
    }
    if (add_objects_after_update_register_call) {
        expect_event_message(base, edgeclient_update_register_msg_cb, true /* succeeds */);
        mock().expectOneCall("MbedCloudClient::add_objects");
        mock().expectOneCall("MbedCloudClient::register_update");
        evbase_mock_call_assigned_event_cb(base, false);
    }
}

static void receive_on_registered_callback(edgeClientStatus_e expected_status,
                                           struct event_base *base,
                                           SetResourceParams *params,
                                           bool add_objects_after_update_register_call,
                                           bool interrupt_received)
{
    /* assume edge-client is registered */
    client_data->edgeclient_status = REGISTERED;

    if (params) {
        mock().expectOneCall("M2MBase::name")
                .withPointerParameter("this", params->endpoint)
                .andReturnValue(params->endpoint_name->c_str());
        mock().expectOneCall("M2MEndpoint::is_deleted").andReturnValue(false);
    }
    mock().expectOneCall("MbedCloudClient::add_objects");
    if (params) {
        mock().expectOneCall("MbedCloudClient::add_object_stub");
    }
    mock().expectOneCall("MbedCloudClient::register_update");
    edgeclient_update_register();
    // evbase_mock_call_assigned_event_cb(base, false);
    if (add_objects_after_update_register_call) {
        edgeclient_set_update_register_needed();
    }
    on_registered_expectations(base);
    edgeclient_on_registered_callback();

    on_registered_safe_expectations(base, params, add_objects_after_update_register_call, interrupt_received);
    evbase_mock_call_assigned_event_cb(base, false);
    CHECK(expected_status == client_data->edgeclient_status);
}

TEST(edge_client, test_edge_client_on_registered_callback)
{
    struct event_base *base = evbase_mock_new();
    receive_on_registered_callback(REGISTERED,
                                   base,
                                   NULL,
                                   false /* add_objects_in_between */,
                                   false /* interrupt_received */);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_edge_client_on_registered_callback_with_interrupt_received)
{
    struct event_base *base = evbase_mock_new();
    client->set_interrupt_received();
    receive_on_registered_callback(REGISTERED,
                                   base,
                                   NULL,
                                   false /* add_objects_in_between */,
                                   true /* interrupt_received */);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_edge_client_on_registered_callback_2nd_with_interrupt_received_add_objects_in_between)
{
    struct event_base *base = evbase_mock_new();
    client->set_interrupt_received();
    receive_on_registered_callback(REGISTERING,
                                   base,
                                   NULL,
                                   true /* add_objects_in_between */,
                                   true /* interrupt_received */);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_edge_client_on_unregistered_callback_msg_api_msg_fails)
{
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, edgeclient_on_unregistered_callback_safe, false /* succeeds */);
    edgeclient_on_unregistered_callback();
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_edge_client_on_unregistered_callback)
{
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, edgeclient_on_unregistered_callback_safe, true /* succeeds */);
    edgeclient_on_unregistered_callback();
    mock().expectOneCall("unregister_dummy");
    evbase_mock_call_assigned_event_cb(base, true);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_update_register_conditional_locking_mutex)
{
    edgeclient_update_register_conditional();
    mock().checkExpectations();
}

TEST(edge_client, test_update_register)
{
    edgeclient_update_register();
    mock().checkExpectations();
}

TEST(edge_client, test_stop_without_endpoints_while_registered)
{
    struct event_base *base = evbase_mock_new();
    receive_on_registered_callback(REGISTERED,
                                   base,
                                   NULL,
                                   false /* add_objects_in_between */,
                                   false /* interrupt_received */);
    mock().expectOneCall("edgeserver_remove_protocol_translator_nodes")
            .andReturnValue(false);
    mock().expectOneCall("edgeserver_graceful_shutdown");
    CHECK_EQUAL(true, edgeclient_stop());
    CHECK_EQUAL(false, client_data->m2m_resources_added_or_removed);
    CHECK_EQUAL(true, client->is_interrupt_received());
    CHECK_EQUAL(REGISTERED, client_data->edgeclient_status);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_stop_without_endpoints_while_registering)
{
    CHECK_EQUAL(REGISTERING, client_data->edgeclient_status);
    mock().expectOneCall("edgeserver_remove_protocol_translator_nodes")
            .andReturnValue(false);
    CHECK_EQUAL(true, edgeclient_stop());
    CHECK_EQUAL(false, client_data->m2m_resources_added_or_removed);
    CHECK_EQUAL(true, client->is_interrupt_received());
    CHECK_EQUAL(REGISTERING, client_data->edgeclient_status);
    mock().checkExpectations();
}

TEST(edge_client, test_stop_with_endpoint_while_registered_with_update_registration)
{
    struct event_base *base = evbase_mock_new();
    SetResourceParams params("test", "3300", 0, "0", "", "100 K", strlen("100 K"), "100 K", M2MBase::GET_ALLOWED);
    set_resource_value(params);
    // Expect registering state, because these new objects have not yet been registered
    receive_on_registered_callback(REGISTERED,
                                   base,
                                   &params,
                                   false /* add_objects_in_between */,
                                   false /* interrupt_received */);
    mock().expectOneCall("edgeserver_remove_protocol_translator_nodes")
            .andReturnValue(true);
    expect_find_endpoint_with_name("test", params.endpoint, params.ctx);
    expect_endpoint_destructor(params.endpoint);
    mock().expectOneCall("MbedCloudClient::add_objects");
    mock().expectOneCall("MbedCloudClient::register_update");
    edgeclient_stop();
    CHECK_EQUAL(false, client_data->m2m_resources_added_or_removed);
    // Issue 2nd stop to print the warning trace
    mock().expectOneCall("edgeserver_exit_event_loop");
    CHECK_EQUAL(false, edgeclient_stop());
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_stop_with_endpoint_while_registered_2nd_with_update_registration_objects_added_in_between)
{
    struct event_base *base = evbase_mock_new();
    SetResourceParams params("test", "3300", 0, "0", "", "100 K", strlen("100 K"), "100 K", M2MBase::GET_ALLOWED);
    set_resource_value(params);
    // Expect registering state, because these new objects have not yet been registered
    receive_on_registered_callback(REGISTERING,
                                   base,
                                   &params,
                                   true /* add_objects_in_between */,
                                   false /* interrupt_received */);
    mock().expectOneCall("edgeserver_remove_protocol_translator_nodes").andReturnValue(true);
    expect_find_endpoint_with_name("test", params.endpoint, params.ctx);
    expect_endpoint_destructor(params.endpoint);
    edgeclient_stop();
    CHECK_EQUAL(true, client_data->m2m_resources_added_or_removed);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_stop_with_endpoint_while_registered_without_update_registration)
{
    struct event_base *base = evbase_mock_new();
    receive_on_registered_callback(REGISTERED,
                                   base,
                                   NULL,
                                   false /* add_objects_in_between */,
                                   false /* interrupt_received */);
    mock().expectOneCall("edgeserver_remove_protocol_translator_nodes")
            .andReturnValue(true);
    mock().expectOneCall("edgeserver_graceful_shutdown");
    edgeclient_stop();
    CHECK_EQUAL(false, client_data->m2m_resources_added_or_removed);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

static M2MEndpoint *add_endpoint_expectations(String &endpoint_name, void *ctx)
{
    char *name = (char *) endpoint_name.c_str();
    String path_name = String("d/");
    path_name += endpoint_name;
    char *path = strdup((char *)path_name.c_str());
    CHECK_FALSE(edgeclient_endpoint_exists(name));
    M2MEndpoint *ep = create_endpoint(endpoint_name, path);

    mock().expectOneCall("M2MInterfaceFactory::create_endpoint")
            .withStringParameter("name", name)
            .andReturnValue((void *) ep);

    mock().expectOneCall("M2MEndpoint::set_context")
            .withPointerParameter("ctx", ctx);
    return ep;
}

static void expect_endpoint_destructor(M2MEndpoint *endpoint)
{
    mock().expectOneCall("MbedCloudClient::remove_object")
            .withPointerParameter("object", (void *) endpoint);
    mock()
        .expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", (void *) endpoint);
    mock()
        .expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", endpoint);
}

static void remove_existing_endpoint_expectations(M2MEndpoint *endpoint)
{
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", (void *)endpoint)
            .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MBase::name")
        .withPointerParameter("this", (void *) endpoint)
        .andReturnValue("test");
    mock().expectOneCall("M2MEndpoint::set_deleted");
}

TEST(edge_client, test_add_endpoint)
{
    String endpoint_name("test");
    M2MEndpoint *endpoint = add_endpoint_expectations(endpoint_name, (void*) TEST_CLIENT_CTX);

    edgeclient_add_endpoint(endpoint_name.c_str(), (void *) TEST_CLIENT_CTX);
    for(int32_t i=0; i<2 ; i++) {
        mock().expectOneCall("M2MBase::base_type")
                .withPointerParameter("this", (void *) endpoint)
                .andReturnValue((int) M2MBase::ObjectDirectory);
        mock()
            .expectOneCall("M2MBase::name")
            .withPointerParameter("this", (void *) endpoint)
            .andReturnValue(endpoint_name.c_str());
    }
    CHECK_TRUE(edgeclient_endpoint_exists(endpoint_name.c_str()));
    CHECK_FALSE(edgeclient_endpoint_exists("test_not_exist"));
    mock().checkExpectations();
}

TEST(edge_client, test_remove_endpoint)
{
    String endpoint_name("test");
    M2MEndpoint *endpoint = add_endpoint_expectations(endpoint_name, (void*) TEST_CLIENT_CTX);
    edgeclient_add_endpoint(endpoint_name.c_str(), (void *) TEST_CLIENT_CTX);
    remove_existing_endpoint_expectations(endpoint);
    edgeclient_remove_endpoint(endpoint_name.c_str());
    mock().checkExpectations();
}

static M2MEndpoint *create_endpoint(String &name, char *path)
{
    mock().disable();
    M2MEndpoint *ep = TestFactory::create_endpoint(name, path);
    mock().enable();
    return ep;
}

static M2MObject *create_object(String &object_id, char *path, bool external_blockwise_store)
{
    mock().disable();
    M2MObject *object = TestFactory::create_object(object_id, path, false);
    mock().enable();
    return object;
}

static M2MObjectInstance *create_object_instance(M2MObject *parent)
{
    mock().disable();
    M2MObjectInstance *object_instance = TestFactory::create_object_instance(*parent);
    mock().enable();
    return object_instance;
}

static M2MResource *create_resource(M2MObjectInstance *parent, String &resource_name)
{
    char *path = NULL;
    bool multiple_instance = false;
    bool external_blockwise_store = false;
    mock().disable();
    M2MResource *resource = TestFactory::create_resource(*parent, resource_name, path, multiple_instance, external_blockwise_store);
    mock().enable();
    return resource;
}

static void find_endpoint_expectations(M2MEndpoint *endpoint, String &endpoint_name)
{
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", (void *) endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MBase::name")
        .withPointerParameter("this", (void *) endpoint)
        .andReturnValue(endpoint_name.c_str());
}

static void find_endpoint_object_expectations(M2MObject *object, const char *object_id)
{
    mock().expectOneCall("M2MEndpoint::object")
            .withStringParameter("name", object_id)
            .andReturnValue((void *) object);
}

static void find_object_type_id_expectations(M2MObject *object, const char *object_id)
{
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", (void *) object)
            .andReturnValue(M2MBase::Object);
    mock().expectOneCall("M2MBase::name_id")
            .andReturnValue(atoi(object_id));
}

static void find_object_instance_expectations(M2MObject *object, M2MObjectInstance *object_instance, uint16_t inst_id)
{
    mock().expectOneCall("M2MObject::object_instance")
            .withPointerParameter("this", object)
            .withUnsignedIntParameter("inst_id", inst_id)
            .andReturnValue((void *) object_instance);
}

static void create_dynamic_resource_expectations(String &resource_id,
                                                 const char *resource_type,
                                                 M2MResource *created_resource,
                                                 Lwm2mResourceType type)
{
    mock().expectOneCall("M2MObjectInstance::create_dynamic_resource")
            .withStringParameter("resource_name", resource_id.c_str())
            .withStringParameter("resource_type", resource_type)
            .withIntParameter("type", (int32_t) type)
            .withBoolParameter("observable", true)
            .withBoolParameter("multiple_instance", false)
            .withBoolParameter("external_blockwise_store", false)
            .andReturnValue((void *) created_resource);
}

static void find_resource_expectations(M2MObjectInstance *object_instance, String &resource_name, M2MResource *resource)
{
    mock().expectOneCall("M2MObjectInstance::resource")
            .withPointerParameter("this", (void *) object_instance)
            .withStringParameter("resource_name", resource_name.c_str())
            .andReturnValue((void *) resource);
}

static void find_existing_endpoint_expectations(M2MEndpoint *endpoint, String &endpoint_name)
{
    find_endpoint_expectations(endpoint, endpoint_name);
}

static void find_existing_object_expectations(M2MEndpoint *endpoint,
                                              String &endpoint_name,
                                              M2MObject *object,
                                              const char *object_id)
{
    find_existing_endpoint_expectations(endpoint, endpoint_name);
    find_endpoint_object_expectations(object, object_id);
}

static void find_existing_object_instance_expectations(M2MEndpoint *endpoint,
                                                       String &endpoint_name,
                                                       M2MObject *object,
                                                       const char *object_id,
                                                       M2MObjectInstance *object_instance,
                                                       uint16_t inst_id)
{
    find_existing_object_expectations(endpoint, endpoint_name, object, object_id);
    find_object_instance_expectations(object, object_instance, inst_id);
}

static void find_existing_resource_expectations(M2MEndpoint *endpoint,
                                                String &endpoint_name,
                                                M2MObject *object,
                                                const char *object_id,
                                                M2MObjectInstance *object_instance,
                                                uint16_t inst_id,
                                                M2MResource *resource,
                                                String &resource_name)
{
    find_existing_object_instance_expectations(endpoint, endpoint_name, object, object_id, object_instance, inst_id);
    find_resource_expectations(object_instance, resource_name, resource);
}

static void find_existing_resource_easy_expectations(SetResourceParams &params)
{
    find_existing_resource_expectations(params.endpoint,
                                        *(params.endpoint_name),
                                        params.object,
                                        params.object_id.c_str(),
                                        params.object_instance,
                                        params.object_instance_id,
                                        params.resource,
                                        params.resource_id);
}

static void add_resource_expectations(SetResourceParams &params)
{
    const char *endpoint_name = NULL;
#if 0 // enable this to help debugging
    mock().strictOrder();
    printf("endpoint: %p\n", params.endpoint);
    printf("object: %p\n", params.object);
    printf("object_instance: %p\n", params.object_instance);
    printf("resource: %p\n", params.resource);
#endif
    if (params.endpoint_name) {
        endpoint_name = params.endpoint_name->c_str();
    }
    if (endpoint_name) {
        params.endpoint = add_endpoint_expectations(*params.endpoint_name, params.ctx);
        mock().expectOneCall("M2MBase::base_type")
                .withPointerParameter("this", params.endpoint)
                .andReturnValue((int) M2MBase::ObjectDirectory);
        mock().expectOneCall("M2MBase::name")
                .withPointerParameter("this", (void *) params.endpoint)
                .andReturnValue(endpoint_name);
        mock().expectOneCall("M2MEndpoint::create_object")
                .withPointerParameter("this", (void *) params.endpoint)
                .withStringParameter("name", params.object_id.c_str())
                .andReturnValue((void *) params.object);
    } else {
        expect_create_object(params.object_id, params.object);
        // add the object to unregistered objects
        find_object_type_id_expectations(params.object, params.object_id.c_str());
    }
    if (endpoint_name) {
        mock().expectOneCall("M2MObject::set_endpoint").withPointerParameter("this", (void *) params.object);
        mock().expectOneCall("M2MBase::base_type")
                .withPointerParameter("this", params.endpoint)
                .andReturnValue((int) M2MBase::ObjectDirectory);
        mock().expectOneCall("M2MBase::name")
                .withPointerParameter("this", (void *) params.endpoint)
                .andReturnValue(endpoint_name);
        find_endpoint_object_expectations(params.object, params.object_id.c_str());
    }
    find_object_instance_expectations(params.object, NULL, params.object_instance_id);
    if (endpoint_name) {
        find_endpoint_expectations(params.endpoint, *params.endpoint_name);
        find_endpoint_object_expectations(params.object, params.object_id.c_str());
    } else {
        find_object_type_id_expectations(params.object, params.object_id.c_str());
    }

    mock().expectOneCall("M2MObject::create_object_instance")
            .withPointerParameter("this", (void *) params.object)
            .withUnsignedIntParameter("instance_id", params.object_instance_id)
            .andReturnValue((void *) params.object_instance);

    if (endpoint_name) {
        find_endpoint_expectations(params.endpoint, *params.endpoint_name);
        find_endpoint_object_expectations(params.object, params.object_id.c_str());
    } else {
        find_object_type_id_expectations(params.object, params.object_id.c_str());
    }
    find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);
    find_resource_expectations(params.object_instance, params.resource_id, NULL);
    if (endpoint_name) {
        find_endpoint_expectations(params.endpoint, *params.endpoint_name);
        find_endpoint_object_expectations(params.object, params.object_id.c_str());
    } else {
        find_object_type_id_expectations(params.object, params.object_id.c_str());
    }

    find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);

    create_dynamic_resource_expectations(params.resource_id, params.resource_type, params.resource, params.value_type);
    mock().expectOneCall("M2MBase::set_operation")
            .withPointerParameter("this", params.resource)
            .withIntParameter("opr", (int32_t) params.operation);
    mock().expectOneCall("M2MBase::set_max_age").withIntParameter("max_age", 60);

    if (params.operation & (M2MBase::POST_ALLOWED | M2MBase::PUT_ALLOWED)) {
        if (endpoint_name) {
            mock().expectOneCall("M2MBase::base_type")
                .withPointerParameter("this", params.endpoint)
                .andReturnValue(M2MBase::ObjectDirectory);
            mock().expectOneCall("M2MBase::name")
                    .withPointerParameter("this", params.endpoint)
                    .andReturnValue(endpoint_name);
            mock().expectOneCall("M2MEndpoint::object")
                .withStringParameter("name", params.object_id.c_str())
                .andReturnValue(params.object);
        } else {
            find_object_type_id_expectations(params.object, params.object_id.c_str());
        }

        mock().expectOneCall("M2MObject::get_endpoint")
                .withPointerParameter("this", params.object)
                .andReturnValue(params.endpoint);
        if (params.endpoint) {
            mock().expectOneCall("M2MEndpoint::get_context")
                .withPointerParameter("this", params.endpoint)
                .andReturnValue(params.ctx);
        }
        mock().expectOneCall("M2MBase::set_async_coap_request_cb")
                .withPointerParameter("this", params.resource)
                .withPointerParameter("callback", (void *) edgeclient_handle_async_coap_request_cb)
                .andReturnValue(true);
    }
    if (endpoint_name) {
        mock().expectOneCall("M2MBase::uri_path")
                .withPointerParameter("this", (void *) params.resource)
                .andReturnValue("d/test/0/0");
    }
 }

 static void get_existing_resource_expectations(SetResourceParams &params)
 {
     if (params.endpoint_name) {
         find_endpoint_expectations(params.endpoint, *params.endpoint_name);
         find_endpoint_object_expectations(params.object, params.object_id.c_str());
     } else {
         find_object_type_id_expectations(params.object, params.object_id.c_str());
     }
     find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);
     find_resource_expectations(params.object_instance, params.resource_id, params.resource);
}

static ValuePointer *set_resource_value_expectations(SetResourceParams &params)
{
   add_resource_expectations(params);
   get_existing_resource_expectations(params);

   ValuePointer *vp = new ValuePointer((uint8_t *) params.text_format_value, params.text_format_value_length);
    if (params.value) {
        mock().expectOneCall("M2MResourceBase::update_value")
                .withParameterOfType("ValuePointer", "value", (void *) vp);
    }
    return vp;
}

static void set_resource_value(SetResourceParams &params)
{
    ValuePointer *vp = set_resource_value_expectations(params);
    const char *endpoint_name = NULL;
    if (params.endpoint_name) {
        endpoint_name = params.endpoint_name->c_str();
    }

    CHECK_EQUAL(PT_API_SUCCESS,
                edgeclient_set_resource_value(endpoint_name,
                                              atoi(params.object_id.c_str()),
                                              params.object_instance_id,
                                              atoi(params.resource_id.c_str()),
                                              params.resource_type,
                                              (const uint8_t *) params.value,
                                              params.value_length,
                                              params.value_type,
                                              params.operation,
                                              (void *) params.ctx /*ctx*/));

    mock().checkExpectations();
    delete vp;
}

TEST(edge_client, test_update_resource_value_not_found)
{
    CHECK(PT_API_RESOURCE_NOT_FOUND ==
          edgeclient_update_resource_value("sample_endpoint", 1, 2, 3, (const uint8_t *) "QEcHSP//kFU=", 12));
    mock().checkExpectations();
}

TEST(edge_client, test_update_resource_value_found_value_wrong_type)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_resource_easy_expectations(params);
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::TIME);

    pt_api_result_code_e
            ret = edgeclient_update_resource_value(ENDPOINT_NAME, 3300, 0, 0, (const uint8_t *) "QEcHSP//kFU=", 12);
    CHECK(PT_API_ILLEGAL_VALUE == ret);
    mock().checkExpectations();
}

TEST(edge_client, test_update_resource_value_found_value_not_writable)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::NOT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_resource_easy_expectations(params);
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::FLOAT);
    const char *encoded_value = "QEcHSP//kFU=";
    uint32_t decoded_len = apr_base64_decode_len(encoded_value);
    uint8_t *resource_value = (uint8_t *) malloc(decoded_len);
    CHECK(NULL != resource_value);
    uint32_t decoded_len2 = apr_base64_decode_binary(resource_value, encoded_value);
    assert(decoded_len >= decoded_len2);
    mock().expectOneCall("M2MBase::operation").andReturnValue(M2MBase::NOT_ALLOWED);

    pt_api_result_code_e ret = edgeclient_update_resource_value(ENDPOINT_NAME,
                                                                3300,
                                                                0,
                                                                0,
                                                                (const uint8_t *) resource_value,
                                                                decoded_len2);
    CHECK(PT_API_RESOURCE_NOT_WRITABLE == ret);
    free(resource_value);
    mock().checkExpectations();
}

TEST(edge_client, test_update_resource_value_found_value_success)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_resource_easy_expectations(params);
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::FLOAT);
    const char *encoded_value = "QEcHSP//kFU=";
    uint32_t decoded_len = apr_base64_decode_len(encoded_value);
    uint8_t *resource_value = (uint8_t *) malloc(decoded_len);
    CHECK(NULL != resource_value);
    uint32_t decoded_len2 = apr_base64_decode_binary(resource_value, encoded_value);
    assert(decoded_len >= decoded_len2);
    mock().expectOneCall("M2MBase::operation").andReturnValue(M2MBase::PUT_ALLOWED);
    const char *expected_value = "\x034\x036\x02e\x030\x035\x036\x039\x031\x035\x032\x038\x033\x030\x030\x030\x030\x030"
                                 "\x032\x031\x035";
    ValuePointer vp((uint8_t *) expected_value, 20);

    mock().expectOneCall("M2MResourceBase::update_value").withParameterOfType("ValuePointer", "value", &vp);

    pt_api_result_code_e ret = edgeclient_update_resource_value(ENDPOINT_NAME,
                                                                3300,
                                                                0,
                                                                0,
                                                                (const uint8_t *) resource_value,
                                                                decoded_len2);
    CHECK(PT_API_SUCCESS == ret);
    free(resource_value);
    mock().checkExpectations();
}

TEST(edge_client, test_get_endpoint_context)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    void *ctx;
    find_existing_endpoint_expectations(params.endpoint, *params.endpoint_name);
    mock().expectOneCall("M2MEndpoint::get_context")
            .withPointerParameter("this", params.endpoint)
            .andReturnValue(params.ctx);
    mock().expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(false);
    bool success = edgeclient_get_endpoint_context(ENDPOINT_NAME, &ctx);
    CHECK(true == success);
    CHECK((void *) TEST_CLIENT_CTX == ctx);
    mock().checkExpectations();
}

TEST(edge_client, test_get_endpoint_deleted_context)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    void *ctx;
    find_existing_endpoint_expectations(params.endpoint, *params.endpoint_name);
    mock().expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(true);
    bool success = edgeclient_get_endpoint_context(ENDPOINT_NAME, &ctx);
    CHECK(false == success);
    CHECK(NULL == ctx);
    mock().checkExpectations();
}

TEST(edge_client, test_get_endpoint_context_endpoint_not_found)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    void *ctx;
    find_existing_endpoint_expectations(params.endpoint, *params.endpoint_name);
    bool success = edgeclient_get_endpoint_context("non-existing-ep-name", &ctx);
    CHECK(false == success);
    CHECK((void *) NULL == ctx);
    mock().checkExpectations();
}

TEST(edge_client, test_get_resource_attributes)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_resource_easy_expectations(params);
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::INTEGER);
    mock().expectOneCall("M2MBase::operation").andReturnValue((int32_t) M2MResourceBase::PUT_ALLOWED);
    edgeclient_resource_attributes_t attributes;
    bool success = edgeclient_get_resource_attributes(params.endpoint_name->c_str(), 3300, 0, 0, &attributes);
    CHECK(true == success);
    CHECK(OPERATION_WRITE == attributes.operations_allowed);
    CHECK(LWM2M_INTEGER == attributes.type);
    mock().checkExpectations();
}

TEST(edge_client, test_get_resource_attributes_not_found)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);

    find_existing_endpoint_expectations(params.endpoint, *params.endpoint_name);

    edgeclient_resource_attributes_t attributes;
    bool success = edgeclient_get_resource_attributes("non-existing-endpoint", 3300, 0, 0, &attributes);
    CHECK(false == success);
    mock().checkExpectations();
}

TEST(edge_client, test_get_resource_value_and_attributes_no_given_ret_value)
{
    edgeclient_resource_attributes_t attributes;
    uint32_t value_length;
    bool success = edgeclient_get_resource_value_and_attributes("non-existing-endpoint",
                                                                3300,
                                                                0,
                                                                0,
                                                                NULL,
                                                                &value_length,
                                                                &attributes);
    CHECK(false == success);
    mock().checkExpectations();
}

TEST(edge_client, test_get_resource_value_and_attributes)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_resource_easy_expectations(params);
    uint8_t *returned_value = (uint8_t *) "";
    uint32_t returned_size = 1;
    mock().expectOneCall("M2MResourceBase::get_value")
            .withPointerParameter("this", params.resource)
            .withOutputParameterReturning("value", &returned_value, sizeof(uint32_t *))
            .withOutputParameterReturning("value_length", &returned_size, sizeof(uint32_t));
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::INTEGER);
    mock().expectOneCall("M2MBase::operation").andReturnValue((int32_t) M2MResourceBase::PUT_ALLOWED);
    edgeclient_resource_attributes_t attributes;
    uint8_t *value;
    uint32_t value_length;
    bool success = edgeclient_get_resource_value_and_attributes(params.endpoint_name->c_str(),
                                                                3300,
                                                                0,
                                                                0,
                                                                &value,
                                                                &value_length,
                                                                &attributes);
    CHECK(true == success);
    CHECK(OPERATION_WRITE == attributes.operations_allowed);
    CHECK(LWM2M_INTEGER == attributes.type);
    mock().checkExpectations();
}

TEST(edge_client, test_get_resource_value_and_attributes_not_found)
{
    SetResourceParams params(ENDPOINT_NAME,
                             "3300",
                             0,
                             "0",
                             "",
                             "100 K",
                             strlen("100 K"),
                             "100 K",
                             M2MBase::PUT_ALLOWED,
                             (void *) TEST_CLIENT_CTX,
                             LWM2M_OPAQUE);
    set_resource_value(params);
    find_existing_endpoint_expectations(params.endpoint, *(params.endpoint_name));
    edgeclient_resource_attributes_t attributes;
    uint8_t *value;
    uint32_t value_length;
    bool success = edgeclient_get_resource_value_and_attributes("non-existing-endpoint",
                                                                3300,
                                                                0,
                                                                0,
                                                                &value,
                                                                &value_length,
                                                                &attributes);
    CHECK(false == success);
    mock().checkExpectations();
}

static void set_resource_value_write_test(bool write_fails, M2MBase::Operation m2m_operation, uint8_t operation)
{
    const uint8_t token[] = {0x62, 0xfc, 0x8c};
    SetResourceParams params(ENDPOINT_NAME, "3300", 0, "0", "", "100 K", strlen("100 K"), "100 K", M2MBase::GET_ALLOWED);
    set_resource_value(params);
    ValuePointer null_response = ValuePointer(NULL, 0);
    // Add another resource with POST_ALLOWED
    find_endpoint_expectations(params.endpoint, *params.endpoint_name);
    find_endpoint_object_expectations(params.object, params.object_id.c_str());
    find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);

    String resource2_name = to_str(TEST_RESOURCE_ID_2);
    M2MResource *resource_2 = create_resource(params.object_instance, resource2_name);
    find_resource_expectations(params.object_instance, resource2_name, NULL);
    find_endpoint_expectations(params.endpoint, *params.endpoint_name);
    find_endpoint_object_expectations(params.object, params.object_id.c_str());
    find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);
    create_dynamic_resource_expectations(resource2_name, params.resource_type, resource_2, LWM2M_STRING);
    mock().expectOneCall("M2MBase::set_operation")
            .withPointerParameter("this", resource_2)
            .withIntParameter("opr", (int32_t) M2MBase::POST_ALLOWED | M2MBase::PUT_ALLOWED);
    mock().expectOneCall("M2MBase::set_max_age").withIntParameter("max_age", 60);

    find_endpoint_expectations(params.endpoint, *params.endpoint_name);
    find_endpoint_object_expectations(params.object, params.object_id.c_str());
    mock().expectOneCall("M2MObject::get_endpoint")
            .withPointerParameter("this", params.object)
            .andReturnValue(params.endpoint);
    mock().expectOneCall("M2MEndpoint::get_context")
            .withPointerParameter("this", params.endpoint)
            .andReturnValue(params.ctx);
    mock().expectOneCall("M2MBase::set_async_coap_request_cb")
            .withPointerParameter("this", resource_2)
            .withPointerParameter("callback", (void *) edgeclient_handle_async_coap_request_cb)
            .andReturnValue(true);
    mock().expectOneCall("M2MBase::uri_path")
            .withPointerParameter("this", (void *) resource_2)
            .andReturnValue("d/test/3300/0/0");

    CHECK_EQUAL(true,
                edgeclient_add_resource(ENDPOINT_NAME,
                                        3300,
                                        0,
                                        TEST_RESOURCE_ID_2,
                                        "",
                                        LWM2M_STRING,
                                        M2MBase::POST_ALLOWED | M2MBase::PUT_ALLOWED,
                                        NULL /* connection */));

    EdgeClientRequestContext request_ctx("test",
                                         3300,
                                         0,
                                         TEST_RESOURCE_ID_2,
                                         (uint8_t *) EXECUTABLE_PATH,
                                         strlen(EXECUTABLE_PATH),
                                         (uint8_t *) token,
                                         3,
                                         operation,
                                         NULL,
                                         NULL,
                                         (void *) TEST_CLIENT_CTX);

    int write_ret_val = 0;
    if (write_fails) {
        write_ret_val = 1;
    }

    mock().expectOneCall("write_to_pt_dummy")
            .withParameterOfType("EdgeClientRequestContext", "request_ctx", &request_ctx)
            .withPointerParameter("userdata", (void *) TEST_CLIENT_CTX)
            .andReturnValue(write_ret_val);

    M2MBase::handle_async_coap_request_cb callback = (M2MBase::handle_async_coap_request_cb)
            M2MCallbackStorage::get_callback(*resource_2, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    M2MCallbackAssociation *association = M2MCallbackStorage::
            get_association_item(*resource_2, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    void *arguments = association->_client_args;

    const uint8_t token_len = 3;
    mock().expectOneCall("M2MBase::uri_path")
            .withPointerParameter("this", (void *) resource_2)
            .andReturnValue("d/test/3300/0/0");
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", resource_2)
            .andReturnValue(M2MBase::Resource);
    mock().expectOneCall("M2MBase::operation").andReturnValue(M2MBase::POST_ALLOWED | M2MBase::PUT_ALLOWED);
    mock().expectOneCall("M2MBase::uri_path")
            .withPointerParameter("this", (void *) resource_2)
            .andReturnValue("d/test/3300/0/10001");
    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue((int32_t) M2MResourceBase::STRING);
    ValuePointer token_pointer((uint8_t *) token, 3);
    if (write_fails) {
        mock().expectOneCall("M2MBase::send_async_response_with_code")
                .withParameterOfType("ValuePointer", "payload", (void *) &null_response)
                .withParameterOfType("ValuePointer", "token", (void *) &token_pointer)
                .withIntParameter("code", COAP_RESPONSE_INTERNAL_SERVER_ERROR)
                .andReturnValue(true);
    }
    (*callback)(*resource_2,
                m2m_operation,
                token,
                token_len,
                (uint8_t *) EXECUTABLE_PATH,
                strlen(EXECUTABLE_PATH),
                arguments);

    mock().checkExpectations();
    mock().disable();
    TestFactory::delete_resource(resource_2);
    mock().enable();
}

TEST(edge_client, test_set_resource_value_execute_succeeds)
{
    set_resource_value_write_test(false /* write fails */, M2MBase::POST_ALLOWED, OPERATION_EXECUTE);
    mock().checkExpectations();
}

TEST(edge_client, test_set_resource_value_execute_fails)
{
    set_resource_value_write_test(true /* write fails */, M2MBase::POST_ALLOWED, OPERATION_EXECUTE);
    mock().checkExpectations();
}

TEST(edge_client, test_set_resource_value_write_succeeds)
{
    set_resource_value_write_test(false /* write fails */, M2MBase::PUT_ALLOWED, OPERATION_WRITE);
    mock().checkExpectations();
}

TEST(edge_client, test_set_resource_value_write_fails)
{
    set_resource_value_write_test(true /* write fails */, M2MBase::PUT_ALLOWED, OPERATION_WRITE);
    mock().checkExpectations();
}

static void expect_find_endpoint_with_name(const char *name, M2MEndpoint *endpoint, void *ctx)
{
    mock().expectOneCall("M2MBase::name")
            .withPointerParameter("this", (void *) endpoint)
            .andReturnValue(name);
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", (void *) endpoint)
            .andReturnValue(M2MBase::ObjectDirectory);
    mock().expectOneCall("M2MEndpoint::get_context")
        .withPointerParameter("this", (void *) endpoint)
        .andReturnValue(ctx);
}

TEST(edge_client, test_remove_objects_owned_by_client)
{
    SetResourceParams params("test", "3300", 0, "0", "", "100 K", strlen("100 K"),
                             "100 K", M2MBase::GET_ALLOWED);
    set_resource_value(params);

    SetResourceParams params2("test-2", "3303", 1, "5601", "", "3303 K", strlen("3303 K"),
                              "3303 K", M2MBase::GET_ALLOWED,
                              (void*) TEST_CLIENT_CTX_2);

    /*
     * Iterates again the list of the resources when adding params2
     * and removing the params
     */
    mock().expectNCalls(12, "M2MBase::base_type")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(12, "M2MBase::name")
        .withPointerParameter("this", (void *) params.endpoint)
        .andReturnValue(params.endpoint_name->c_str());

    set_resource_value(params2);

    mock().expectNCalls(1, "M2MBase::base_type")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(1, "M2MBase::name")
        .withPointerParameter("this", (void *) params2.endpoint)
        .andReturnValue(params2.endpoint_name->c_str());
    mock().expectNCalls(1, "M2MEndpoint::get_context")
        .withPointerParameter("this", (void *) params2.endpoint)
        .andReturnValue(params2.ctx);

    expect_find_endpoint_with_name("test", params.endpoint, params.ctx);
    expect_endpoint_destructor(params.endpoint);
    edgeclient_remove_objects_owned_by_client((void *) TEST_CLIENT_CTX);

    expect_find_endpoint_with_name("test-2", params2.endpoint, params2.ctx);
    expect_endpoint_destructor(params2.endpoint);
    edgeclient_remove_objects_owned_by_client((void *) TEST_CLIENT_CTX_2);
    mock().checkExpectations();
}

TEST(edge_client, test_remove_resources_owned_by_client)
{
    SetResourceParams params("test", "3300", 0, "0", "", "100 K", strlen("100 K"),
                             "100 K", M2MBase::GET_ALLOWED);
    set_resource_value(params);
    edgeclient_remove_resources_owned_by_client((void *) TEST_CLIENT_CTX);
    mock().checkExpectations();
}

TEST(edge_client, test_remove_resources_owned_by_client_with_resource_list)
{
    /* indirect testing with double values */
    double *test_value = (double*) calloc(1, sizeof(double));
    char *returned_value = (char *) "0.00000000000000000";
    size_t returned_value_length = strlen(returned_value);
    ValuePointer test_value_pointer((const uint8_t*) returned_value, returned_value_length);

    SetResourceParams params("test-ep", "3303", 0, "5601", "", "100 K", strlen("100 K"),
                             "100 K", M2MBase::POST_ALLOWED);
    set_resource_value(params);

    SetResourceParams params2("test-ep2", "3305", 1, "5602", "", "500 K", strlen("500 K"),
                              "500 K", M2MBase::GET_ALLOWED,
                              (void*) TEST_CLIENT_CTX_2);

    /*
     * Iterates again the list of the resources when adding params2
     * and removing the params
     */
    mock().expectNCalls(12, "M2MBase::base_type")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(12, "M2MBase::name")
        .withPointerParameter("this", (void *) params.endpoint)
        .andReturnValue(params.endpoint_name->c_str());

    set_resource_value(params2);

    /* params 1 add_endpoint expectations */
    mock().expectNCalls(7, "M2MBase::base_type")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(7, "M2MBase::name")
        .withPointerParameter("this", (void *) params.endpoint)
        .andReturnValue(params.endpoint_name->c_str());
    mock().expectNCalls(5, "M2MEndpoint::object")
        .withStringParameter("name", params.object_id.c_str())
        .andReturnValue(params.object);
    mock().expectNCalls(4, "M2MObject::object_instance")
        .withPointerParameter("this", params.object)
        .withIntParameter("inst_id", params.object_instance_id)
        .andReturnValue(params.object_instance);
    mock().expectNCalls(3, "M2MObjectInstance::resource")
        .withPointerParameter("this", params.object_instance)
        .withStringParameter("resource_name", params.resource_id.c_str())
        .andReturnValue(params.resource);
    mock().expectOneCall("M2MResourceBase::update_value")
        .withParameterOfType("ValuePointer", "value", &test_value_pointer);

    edgeclient_add_endpoint(params.endpoint_name->c_str(), (void*) TEST_CLIENT_CTX);
    edgeclient_add_resource(params.endpoint_name->c_str(), 3303, 0, 5601, "", LWM2M_FLOAT,
                            OPERATION_EXECUTE, (void*) TEST_CLIENT_CTX);
    edgeclient_set_resource_value(params.endpoint_name->c_str(), 3303, 0, 5601, "", (uint8_t*) test_value, sizeof(double),
                                  LWM2M_FLOAT, OPERATION_EXECUTE, (void*) TEST_CLIENT_CTX);


    /* params 2 add_endpoint expectations, iterates also the params 1 */
    mock().expectNCalls(7, "M2MBase::base_type")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(7, "M2MBase::name")
        .withPointerParameter("this", (void *) params.endpoint)
        .andReturnValue(params.endpoint_name->c_str());
    mock().expectNCalls(7, "M2MBase::base_type")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(7, "M2MBase::name")
        .withPointerParameter("this", (void *) params2.endpoint)
        .andReturnValue(params2.endpoint_name->c_str());
    mock().expectNCalls(5, "M2MEndpoint::object")
        .withStringParameter("name", params2.object_id.c_str())
        .andReturnValue(params2.object);
    mock().expectNCalls(4, "M2MObject::object_instance")
        .withPointerParameter("this", params2.object)
        .withIntParameter("inst_id", params2.object_instance_id)
        .andReturnValue(params2.object_instance);
    mock().expectNCalls(3, "M2MObjectInstance::resource")
        .withPointerParameter("this", params2.object_instance)
        .withStringParameter("resource_name", params2.resource_id.c_str())
        .andReturnValue(params2.resource);

    edgeclient_add_endpoint(params2.endpoint_name->c_str(), (void*) TEST_CLIENT_CTX_2);
    edgeclient_add_resource(params2.endpoint_name->c_str(), 3305, 1, 5602, "", LWM2M_OPAQUE,
                            OPERATION_READ, (void*) TEST_CLIENT_CTX_2);
    edgeclient_set_resource_value(params2.endpoint_name->c_str(), 3305, 1, 5602, "", NULL, 0,
                                  LWM2M_OPAQUE, OPERATION_READ, (void*) TEST_CLIENT_CTX_2);

    /* Remove params1 */
    edgeclient_remove_resources_owned_by_client((void *) TEST_CLIENT_CTX);

    mock().expectNCalls(1, "M2MBase::base_type")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue(M2MBase::ObjectDirectory);
    mock().expectNCalls(1, "M2MBase::name")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue(params.endpoint_name->c_str());
    mock().expectOneCall("M2MEndpoint::get_context")
        .withPointerParameter("this", params.endpoint)
        .andReturnValue(params.ctx);

    mock().expectNCalls(1, "M2MBase::base_type")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(M2MBase::ObjectDirectory);
    mock().expectNCalls(1, "M2MBase::name")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(params2.endpoint_name->c_str());
    mock().expectOneCall("M2MEndpoint::get_context")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(params2.ctx);

    expect_endpoint_destructor(params.endpoint);

    edgeclient_remove_objects_owned_by_client((void *) TEST_CLIENT_CTX);

    /* Remove params2 */
    mock().expectNCalls(1, "M2MBase::base_type")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(M2MBase::ObjectDirectory);
    mock().expectNCalls(1, "M2MBase::name")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(params2.endpoint_name->c_str());
    mock().expectOneCall("M2MEndpoint::get_context")
        .withPointerParameter("this", params2.endpoint)
        .andReturnValue(params2.ctx);

    expect_endpoint_destructor(params2.endpoint);

    edgeclient_remove_objects_owned_by_client((void *) TEST_CLIENT_CTX_2);

    mock().checkExpectations();
    free(test_value);
}

static void expect_create_object(String &name, M2MObject *object)
{
    mock().expectOneCall("M2MInterfaceFactory::create_object")
            .withStringParameter("name", name.c_str())
            .andReturnValue((void *) object);
}

TEST(edge_client, test_unsupported_executable_edge_core_resource)
{
    int32_t magic_number = 42;
    const char *returned_value = "42";
    const uint8_t token[] = {0x62, 0xfc, 0x8c};
    SetResourceParams params(NULL,
                             to_str(TEST_OBJECT_ID),
                             TEST_OBJECT_INSTANCE_ID,
                             to_str(TEST_RESOURCE_ID),
                             "",
                             NULL,
                             0,
                             returned_value,
                             M2MBase::PUT_ALLOWED,
                             NULL);
    params.set_integer_value(&magic_number);
    String object_name = to_str(TEST_OBJECT_ID);
    set_resource_value(params);

    mock().expectOneCall("M2MBase::uri_path")
            .withPointerParameter("this", params.resource)
            .andReturnValue("100/1000/10000");
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", params.resource)
            .andReturnValue(M2MBase::Resource);
    mock().expectOneCall("M2MBase::operation").andReturnValue(M2MBase::PUT_ALLOWED);
    ValuePointer *payload_pointer = new ValuePointer((uint8_t *) NULL, 0);
    ValuePointer *token_pointer = new ValuePointer((uint8_t *) token, 3);
    // It will fail, because Edge Core doesn't support PUT to resource 100,100,10000
    mock().expectOneCall("M2MBase::send_async_response_with_code")
            .withParameterOfType("ValuePointer", "payload", (void *) payload_pointer)
            .withParameterOfType("ValuePointer", "token", (void *) token_pointer)
            .withIntParameter("code", (int32_t) COAP_RESPONSE_INTERNAL_SERVER_ERROR)
            .andReturnValue(true);

    M2MBase::handle_async_coap_request_cb callback = (M2MBase::handle_async_coap_request_cb)
            M2MCallbackStorage::get_callback(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    M2MCallbackAssociation *association = M2MCallbackStorage::
            get_association_item(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    void *arguments = association->_client_args;
    const uint8_t token_len = 3;
    const uint8_t *buffer = (const uint8_t *) "Hello";
    size_t buffer_size = 5;

    (*callback)(*params.resource, M2MBase::PUT_ALLOWED, token, token_len, buffer, buffer_size, arguments);
    // prevent params deleting the object, because it has been added to the unregistered objects list
    params.object = NULL;
    mock().checkExpectations();
    delete payload_pointer;
    delete token_pointer;
}

TEST(edge_client, test_supported_executable_edge_core_resource)
{
    int32_t magic_number = 42;
    const char *returned_value = "42";
    const uint8_t token[] = {0x62, 0xfc, 0x8c};
    SetResourceParams params(NULL, to_str(3), 0, to_str(5), "", NULL, 0, returned_value, M2MBase::POST_ALLOWED, NULL);
    params.set_integer_value(&magic_number);
    set_resource_value(params);

    mock().expectOneCall("M2MBase::uri_path").withPointerParameter("this", params.resource).andReturnValue("3/0/5");
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", params.resource)
            .andReturnValue(M2MBase::Resource);
    mock().expectOneCall("M2MBase::operation").andReturnValue(M2MBase::POST_ALLOWED);
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, rfs_reset_factory_settings_request_cb, true /* succeeds */);
    M2MBase::handle_async_coap_request_cb callback = (M2MBase::handle_async_coap_request_cb)
            M2MCallbackStorage::get_callback(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    M2MCallbackAssociation *association = M2MCallbackStorage::
            get_association_item(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    void *arguments = association->_client_args;
    const uint8_t token_len = 3;
    const uint8_t *buffer = (const uint8_t *) "Hello";
    size_t buffer_size = 5;

    (*callback)(*params.resource, M2MBase::POST_ALLOWED, token, token_len, buffer, buffer_size, arguments);

    // Don't handle the Msg API event here, because it's tested in test_execute_resource_customer_cb_succeeds below.
    event_message_t *message = (event_message_t *) (base->assigned_event->cb_arg);
    rfs_request_message_t *rfs_message = (rfs_request_message_t *) (message->data);
    free(message->ev);
    edgeclient_deallocate_request_context(rfs_message->request_ctx);
    free(rfs_message);
    free(message);
    // prevent params deleting the object, because it has been added to the unregistered objects list
    params.object = NULL;
    mock().checkExpectations();
    free(base);
}

static edgeclient_request_context_t *alloc_test_context(const char *path, uint8_t operation)
{
    const uint8_t token_data[] = {0x62, 0xfc, 0x8c};

    uint8_t *value = (uint8_t *) strdup("Hello");
    size_t value_len = strlen((char *) value);
    size_t token_len = sizeof(token_data);
    uint8_t *token = (uint8_t *) malloc(token_len);
    memcpy(token, token_data, token_len);
    edge_rc_status_e rc_status;
    edgeclient_request_context_t *context = edgeclient_allocate_request_context(path,
                                                                                value,
                                                                                value_len,
                                                                                token,
                                                                                token_len,
                                                                                EDGECLIENT_VALUE_IN_TEXT,
                                                                                OPERATION_EXECUTE,
                                                                                LWM2M_STRING,
                                                                                NULL, /* success cb */
                                                                                NULL, /* failure cb */
                                                                                &rc_status,
                                                                                NULL /* connection */);
    return context;
}

TEST(edge_client, test_edgeclient_execute_success_resource_not_found)
{
    edgeclient_request_context_t *context = alloc_test_context("d/example-device/100/1000/10001", OPERATION_EXECUTE);
    edgeclient_execute_success(context);
    mock().checkExpectations();
}

static void found_resource_operation_from_cloud_test(
        M2MBase::Operation m2m_operation,
        uint8_t operation,
        edgeclient_response_handler success_handler,
        bool write_illegal_value_1 /* mock returns integer type at first call for "Hello" input */,
        bool write_illegal_value_2 /* mock returns integer type at 2nd call for "Hello" input */)
{
    mock().crashOnFailure();
    bool operation_allowed = (m2m_operation == operation);
    ValuePointer *expected_payload_pointer = NULL;
    const uint8_t token[] = {0x62, 0xfc, 0x8c};
    const uint8_t token_len = 3;
    const uint8_t *buffer = (const uint8_t *) "Hello";
    const char *orig_value = "100 K";
    size_t orig_value_len = strlen("100 K");
    size_t buffer_size = 5;
    coap_response_code_e expected_coap_response_code = COAP_RESPONSE_CHANGED;
    M2MBase::Operation allowed_operations = m2m_operation;

    // If we are testing GET, async feature is currently enabled only if PUT or POST is allowed.
    if ((M2MBase::GET_ALLOWED & m2m_operation) != 0) {
        allowed_operations = (M2MBase::Operation)(M2MBase::POST_ALLOWED | M2MBase::GET_ALLOWED);
    }
    ValuePointer *payload_pointer = new ValuePointer((uint8_t *) buffer, buffer_size);

    SetResourceParams
            params("example-device", "100", 1000, "10001", "", orig_value, orig_value_len, orig_value, allowed_operations);
    set_resource_value(params);

    EdgeClientRequestContext request_ctx("example-device",
                                         100,
                                         1000,
                                         10001,
                                         (uint8_t *) buffer,
                                         buffer_size,
                                         token,
                                         token_len,
                                         operation,
                                         NULL,
                                         NULL,
                                         (void *) TEST_CLIENT_CTX);

    mock().expectOneCall("M2MBase::uri_path")
            .withPointerParameter("this", params.resource)
            .andReturnValue("d/example-device/100/1000/10001");
    mock().expectOneCall("M2MBase::base_type")
            .withPointerParameter("this", params.resource)
            .andReturnValue(M2MBase::Resource);
    mock().expectOneCall("M2MBase::operation").andReturnValue(allowed_operations);
    char *returned_value = strdup(orig_value);
    uint32_t returned_size = strlen(returned_value);
    bool free_returned_value = true;
    M2MBase::handle_async_coap_request_cb callback = (M2MBase::handle_async_coap_request_cb)
            M2MCallbackStorage::get_callback(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);
    M2MCallbackAssociation *association = M2MCallbackStorage::
            get_association_item(*params.resource, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);

    ValuePointer expected_token_pointer(token, 3);
    if (operation_allowed) {
        // expected calls to send the value to protocol translator
        if (operation != OPERATION_READ) {
            mock().expectOneCall("M2MBase::uri_path")
                    .withPointerParameter("this", params.resource)
                    .andReturnValue("d/example-device/100/1000/10001");
            M2MBase::DataType returned_type_1 = M2MBase::OPAQUE;
            if (write_illegal_value_1) {
                returned_type_1 = M2MBase::INTEGER;
            }

            mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue(returned_type_1);
            if (!write_illegal_value_1) {
                mock().expectOneCall("write_to_pt_dummy")
                        .withParameterOfType("EdgeClientRequestContext", "request_ctx", &request_ctx)
                        .withPointerParameter("userdata", (void *) TEST_CLIENT_CTX);
            }
        }
        if (!write_illegal_value_1) {
            if (operation == OPERATION_READ) {
                expected_coap_response_code = COAP_RESPONSE_CONTENT;
                expected_payload_pointer = new ValuePointer((const uint8_t *) orig_value, orig_value_len);
                mock().expectOneCall("M2MResourceBase::get_value")
                        .withPointerParameter("this", params.resource)
                        .withOutputParameterReturning("value", &returned_value, sizeof(uint32_t *))
                        .withOutputParameterReturning("value_length", &returned_size, sizeof(uint32_t));
            }
            else {
                mock().expectOneCall("M2MBase::operation").andReturnValue(allowed_operations);
                find_existing_resource_easy_expectations(params);
                if (!write_illegal_value_2 && ((operation & OPERATION_WRITE) == 0)) {
                    free_returned_value = false; // The returned value is free'd in the function that calls M2MResourceBase::get_value
                    expected_payload_pointer = new ValuePointer((const uint8_t *) orig_value, orig_value_len);
                    mock().expectOneCall("M2MResourceBase::get_value")
                        .withPointerParameter("this", params.resource)
                        .withOutputParameterReturning("value", &returned_value, sizeof(uint32_t *))
                        .withOutputParameterReturning("value_length", &returned_size, sizeof(uint32_t));
                }
                else {
                    expected_payload_pointer = new ValuePointer(NULL, 0);

                }
                if (operation == OPERATION_WRITE) {
                    // expectations when the value is updated
                    M2MBase::DataType returned_type_2 = M2MBase::OPAQUE;
                    if (write_illegal_value_2) {
                        returned_type_2 = M2MBase::INTEGER;
                        expected_coap_response_code = COAP_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
                    }
                    mock().expectOneCall("M2MResourceBase::resource_instance_type").andReturnValue(returned_type_2);
                    if (!write_illegal_value_2) {
                        mock().expectOneCall("M2MBase::operation").andReturnValue(allowed_operations);
                        mock().expectOneCall("M2MResourceBase::update_value")
                                .withParameterOfType("ValuePointer", "value", payload_pointer);
                    }
                    find_existing_resource_easy_expectations(params);
                }
            }
        } else {
            expected_payload_pointer = new ValuePointer(NULL, 0);
            expected_coap_response_code = COAP_RESPONSE_BAD_REQUEST;
        }
    } else {
        expected_payload_pointer = new ValuePointer(NULL, 0);
        expected_coap_response_code = COAP_RESPONSE_METHOD_NOT_ALLOWED;
    }

    mock().expectOneCall("M2MBase::send_async_response_with_code")
            .withParameterOfType("ValuePointer", "payload", (void *) expected_payload_pointer)
            .withParameterOfType("ValuePointer", "token", (void *) &expected_token_pointer)
            .withIntParameter("code", (int32_t) expected_coap_response_code)
            .andReturnValue(true);

    void *arguments = association->_client_args;
    (*callback)(*params.resource, (M2MBase::Operation) operation, token, token_len, buffer, buffer_size, arguments);

    if (operation_allowed && !write_illegal_value_1) {
        // response comes from Protocol Translator
        if (operation != OPERATION_READ) {
            edgeclient_request_context_t *context = alloc_test_context("d/example-device/100/1000/10001", operation);
            (*success_handler)(context);
            if (free_returned_value) {
                free(returned_value);
            }
        }
    } else {
        if (free_returned_value) {
            free(returned_value);
        }
    }
    mock().checkExpectations();
    delete expected_payload_pointer;
    delete payload_pointer;
}

TEST(edge_client, test_edgeclient_async_request_no_uri)
{
    edge_rc_status_e rc_status;
    AsyncCallbackParams acp(NULL);
    bool success = acp.async_request(NULL, M2MBase::PUT_ALLOWED, NULL, 0, NULL, 0, &rc_status);
    CHECK_EQUAL(false, success);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_async_request_unsupported_operation)
{
    edge_rc_status_e rc_status;
    AsyncCallbackParams acp(NULL);
    bool success = acp.set_uri("test-device", 100, 1000, 10001);
    CHECK_EQUAL(true, success);
    success = acp.async_request(NULL, M2MBase::GET_ALLOWED, NULL, 0, NULL, 0, &rc_status);
    CHECK_EQUAL(false, success);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_read_success_resource_found)
{
    found_resource_operation_from_cloud_test(M2MBase::GET_ALLOWED,
                                             OPERATION_READ,
                                             NULL,
                                             false, /* write illegal value 1 */
                                             false /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_execute_success_resource_found)
{
    found_resource_operation_from_cloud_test(M2MBase::POST_ALLOWED,
                                             OPERATION_EXECUTE,
                                             edgeclient_execute_success,
                                             false, /* write illegal value 1 */
                                             false /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_execute_failure_resource_not_found)
{
    edgeclient_request_context_t *context = alloc_test_context("d/example-device/100/1000/10001", OPERATION_EXECUTE);
    edgeclient_execute_failure(context);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_success_resource_not_found)
{
    edgeclient_request_context_t *context = alloc_test_context("d/example-device/100/1000/10001", OPERATION_WRITE);
    edgeclient_write_success(context);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_operation_not_allowed)
{
    found_resource_operation_from_cloud_test(M2MBase::GET_ALLOWED,
                                             OPERATION_WRITE,
                                             edgeclient_write_success,
                                             false, /* write illegal value 1 */
                                             false /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_success_resource_found)
{
    found_resource_operation_from_cloud_test(M2MBase::PUT_ALLOWED,
                                             OPERATION_WRITE,
                                             edgeclient_write_success,
                                             false, /* write illegal value 1 */
                                             false /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_success_resource_found_illegal_value_1)
{
    found_resource_operation_from_cloud_test(M2MBase::PUT_ALLOWED,
                                             OPERATION_WRITE,
                                             edgeclient_write_success,
                                             true, /* write illegal value 1 */
                                             false /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_success_resource_found_illegal_value_2)
{
    found_resource_operation_from_cloud_test(M2MBase::PUT_ALLOWED,
                                             OPERATION_WRITE,
                                             edgeclient_write_success,
                                             false, /* write illegal value 1 */
                                             true /* write illegal value 2 */);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_write_failure_resource_not_found)
{
    edgeclient_request_context_t *context = alloc_test_context("d/example-device/100/1000/10001", OPERATION_WRITE);
    edgeclient_write_failure(context);
    mock().checkExpectations();
}

TEST(edge_client, test_resource_without_endpoint)
{
    int32_t magic_number = 42;
    char* returned_value = strdup("42");
    uint32_t returned_size = strlen(returned_value);

    SetResourceParams params(NULL,
                             to_str(TEST_OBJECT_ID),
                             TEST_OBJECT_INSTANCE_ID,
                             to_str(TEST_RESOURCE_ID),
                             "",
                             NULL,
                             0,
                             returned_value,
                             M2MBase::GET_ALLOWED,
                             NULL);
    params.set_integer_value(&magic_number);
    String object_name = to_str(TEST_OBJECT_ID);
    // Adding resource to non-existing structure should fail.
    CHECK_EQUAL(false,
                edgeclient_add_resource(NULL,
                                        TEST_OBJECT_ID,
                                        TEST_OBJECT_INSTANCE_ID,
                                        TEST_RESOURCE_ID,
                                        "",
                                        LWM2M_INTEGER,
                                        1 /*GET_ALLOWED*/,
                                        NULL /* connection */));
    set_resource_value(params);
    find_object_type_id_expectations(params.object, params.object_id.c_str());
    find_object_instance_expectations(params.object, params.object_instance, params.object_instance_id);
    find_resource_expectations(params.object_instance, params.resource_id, params.resource);
    mock().expectOneCall("M2MResourceBase::get_value")
            .withPointerParameter("this", params.resource)
            .withOutputParameterReturning("value", &returned_value, sizeof(uint32_t *))
            .withOutputParameterReturning("value_length", &returned_size, sizeof(uint32_t));
    char *read_value;
    uint32_t value_length;
    edgeclient_get_resource_value(NULL,
            TEST_OBJECT_ID,
            TEST_OBJECT_INSTANCE_ID,
            TEST_RESOURCE_ID,
            (uint8_t **) &read_value,
            &value_length);
    CHECK_EQUAL(2, value_length);
    STRNCMP_EQUAL("42", read_value, 2);

    // prevent params deleting the object, because it has been added to the unregistered objects list
    params.object = NULL;
    free(returned_value);
    mock().checkExpectations();
}

TEST(edge_client, test_get_internal_id)
{
    ConnectorClientEndpointInfo info(M2MSecurity::NoSecurity);
    info.internal_endpoint_name = "sample_internal_id";
    mock()
        .expectOneCall("MbedCloudClient::endpoint_info")
        .andReturnValue((void *) &info);
    CHECK(strcmp("sample_internal_id", edgeclient_get_internal_id()) == 0);
    mock().checkExpectations();
}

TEST(edge_client, test_get_endpoint_name)
{
    ConnectorClientEndpointInfo info(M2MSecurity::NoSecurity);
    info.endpoint_name = "sample_endpoint_name";
    mock()
        .expectOneCall("MbedCloudClient::endpoint_info")
        .andReturnValue((void *) &info);
    CHECK(strcmp("sample_endpoint_name", edgeclient_get_endpoint_name()) == 0);
    mock().checkExpectations();
}

TEST(edge_client, test_on_error_callback_msg_api_msg_fails)
{
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, edgeclient_on_unregistered_callback_safe, false /* succeeds */);
    edgeclient_on_error_callback(100, "any fatal error");
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_on_error_callback)
{
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, edgeclient_on_unregistered_callback_safe, true /* succeeds */);
    edgeclient_on_error_callback(100, "any fatal error");
    mock().expectOneCall("error_dummy")
            .withIntParameter("error_code", 100)
            .withStringParameter("error_description", "any fatal error");
    evbase_mock_call_assigned_event_cb(base, true);
    mock().checkExpectations();
    evbase_mock_delete(base);
}

TEST(edge_client, test_is_shutting_down)
{
    CHECK(false == edgeclient_is_shutting_down());
    mock().checkExpectations();
}

TEST(edge_client, test_rfs_add_factory_reset_resource)
{
    SetResourceParams params(NULL,
                             to_str(EDGE_DEVICE_OBJECT_ID),
                             0,
                             to_str(EDGE_FACTORY_RESET_RESOURCE_ID),
                             "",
                             NULL,
                             0,
                             NULL,
                             M2MBase::POST_ALLOWED,
                             NULL);
    ValuePointer *vp = set_resource_value_expectations(params);
    rfs_add_factory_reset_resource();
    mock().checkExpectations();
    // prevent params deleting the object, because it has been added to the unregistered objects list
    params.object = NULL;
    mock().checkExpectations();
    delete vp;
}

static void test_execute_resource_success_handler(edgeclient_request_context_t *ctx)
{
    (void) ctx;
    mock().actualCall("test_execute_resource_success_handler");
}

static void test_execute_resource_failure_handler(edgeclient_request_context_t *ctx)
{
    (void) ctx;
    mock().actualCall("test_execute_resource_failure_handler");
}

static edgeclient_request_context_t *allocate_default_test_context()
{
    edgeclient_request_context_t *request_ctx =
            (edgeclient_request_context_t *) malloc(sizeof(edgeclient_request_context_t));
    request_ctx->device_id = NULL;
    request_ctx->object_id = EDGE_DEVICE_OBJECT_ID;
    request_ctx->object_instance_id = 0;
    request_ctx->token = NULL;
    request_ctx->token_len = 0;
    request_ctx->resource_id = EDGE_FACTORY_RESET_RESOURCE_ID;
    request_ctx->value = NULL;
    request_ctx->value_len = 0;
    request_ctx->operation = OPERATION_EXECUTE;
    request_ctx->success_handler = test_execute_resource_success_handler;
    request_ctx->failure_handler = test_execute_resource_failure_handler;
    request_ctx->connection = NULL;
    return request_ctx;
}

static void test_execute_resource_common(bool customer_rfs_succeeds)
{
    edgeclient_request_context_t *request_ctx = allocate_default_test_context();
    struct event_base *base = evbase_mock_new();
    expect_event_message(base, rfs_reset_factory_settings_request_cb, true /* succeeds */);
    edgeserver_resource_async_request(request_ctx);
    mock().expectOneCall("edgeserver_execute_rfs_customer_code").andReturnValue(customer_rfs_succeeds);
    expect_event_message(base, rfs_reset_factory_settings_response_cb, true /* succeeds */);
    if ( customer_rfs_succeeds) {
        mock().expectOneCall("edgeserver_rfs_customer_code_succeeded");
        mock().expectOneCall("edgeserver_graceful_shutdown");
    }

    // the following cb call will launch a thread. Therefore acquire a lock to block this thread
    pthread_mutex_lock(&base->event_lock);
    evbase_mock_call_assigned_event_cb(base, true);
    // we can now relase our lock to becase next callback doesn't need to be blocked. It can run in this main thread.
    pthread_mutex_unlock(&base->event_lock);
    evbase_mock_call_assigned_event_cb(base, true);
    // evbase_mock_call_assigned_event_cb acquired the event_lock. Therefore free it to clean up.
    pthread_mutex_unlock(&base->event_lock);

    free(base);
}

TEST(edge_client, test_execute_resource_customer_cb_succeeds)
{
    test_execute_resource_common(true);
    mock().checkExpectations();
}

TEST(edge_client, test_execute_resource_customer_cb_fails)
{
    test_execute_resource_common(false);
    mock().checkExpectations();
}

TEST(edge_client, test_execute_resource_with_unexpected_parameters)
{
    edgeclient_request_context_t *request_ctx = allocate_default_test_context();
    request_ctx->operation = OPERATION_WRITE;
    edgeserver_resource_async_request(request_ctx);
    mock().checkExpectations();
}

TEST(edge_client, test_finalize_reset_factory_settings_kcm_success)
{
    mock().expectOneCall("kcm_factory_reset")
        .andReturnValue(KCM_STATUS_SUCCESS);
    rfs_finalize_reset_factory_settings();
    mock().checkExpectations();
}

TEST(edge_client, test_finalize_reset_factory_settings_kcm_failure)
{
    mock().expectOneCall("kcm_factory_reset")
        .andReturnValue(KCM_STATUS_ERROR);
    rfs_finalize_reset_factory_settings();
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_verify_value_with_valid_value)
{
    bool value = true;
    const uint8_t *value_buffer = (const uint8_t *) &value;
    const uint8_t value_length = 1;
    CHECK_EQUAL(true, edgeclient_verify_value(value_buffer, value_length, LWM2M_BOOLEAN));
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_verify_value_with_invalid_value)
{
    uint8_t value = 2;
    const uint8_t *value_buffer = &value;
    const uint8_t value_length = 5;
    CHECK_EQUAL(false, edgeclient_verify_value(value_buffer, value_length, LWM2M_BOOLEAN));
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_remove_object_instance)
{
    SetResourceParams
            params("test-end-point", to_str(9000), 101, to_str(TEST_RESOURCE_ID), "", NULL, 0, "", M2MBase::GET_ALLOWED);
    set_resource_value(params);
    find_existing_object_expectations(params.endpoint, *params.endpoint_name, params.object, "9000");

    mock().expectOneCall("M2MObject::remove_object_instance")
            .withPointerParameter("this", params.object)
            .withUnsignedIntParameter("inst_id", 101)
            .andReturnValue(true);
    edgeclient_remove_object_instance("test-end-point", 9000, 101);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_get_account_id)
{
    struct ConnectorClientEndpointInfo *info = new ConnectorClientEndpointInfo(M2MSecurity::NoSecurity);
    info->account_id = "test-account-id";
    mock().expectOneCall("MbedCloudClient::endpoint_info").andReturnValue(info);
    const char *account_id = edgeclient_get_account_id();
    STRCMP_EQUAL("test-account-id", account_id);
    mock().checkExpectations();
    delete info;
}

TEST(edge_client, test_edgeclient_get_lwm2m_server_uri)
{

    struct ConnectorClientEndpointInfo *info = new ConnectorClientEndpointInfo(M2MSecurity::NoSecurity);
    info->lwm2m_server_uri = "https://api-os2.mbedcloudstaging.net";
    mock().expectOneCall("MbedCloudClient::endpoint_info").andReturnValue(info);

    const char *uri = edgeclient_get_lwm2m_server_uri();
    STRCMP_EQUAL("https://api-os2.mbedcloudstaging.net", uri);
    mock().checkExpectations();
    delete info;
}

TEST(edge_client, test_edgeclient_create_byoc_data)
{
    byoc_data_t *byoc_data = edgeclient_create_byoc_data((char *) "certificate.cbor");
    STRCMP_EQUAL("certificate.cbor", byoc_data->cbor_file);
    edgeclient_destroy_byoc_data(byoc_data);

    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_inject_byoc_cert_no_byoc_file)
{
    byoc_data_t *byoc_data = edgeclient_create_byoc_data(NULL);
    int ret_val = edgeclient_inject_byoc(byoc_data);
    CHECK_EQUAL(0, ret_val);
    edgeclient_destroy_byoc_data(byoc_data);

    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_inject_byoc_cert_doesn_t_exist)
{
    byoc_data_t *byoc_data = edgeclient_create_byoc_data((char *) "non-existing-certificate.cbor");
    mock().expectOneCall("edge_read_file").andReturnValue(1);
    int ret_val = edgeclient_inject_byoc(byoc_data);
    CHECK_EQUAL(1, ret_val);
    edgeclient_destroy_byoc_data(byoc_data);

    mock().checkExpectations();
}

TEST_GROUP(error_parser){void setup(){} void teardown(){}};

TEST(error_parser, test_map_to_coap_error)
{
    coap_response_code_e resp;
    resp = map_to_coap_error(PT_API_REQUEST_TIMEOUT);
    CHECK_EQUAL(COAP_RESPONSE_GATEWAY_TIMEOUT, resp);
    resp = map_to_coap_error(PT_API_REMOTE_DISCONNECTED);
    CHECK_EQUAL(COAP_RESPONSE_NOT_FOUND, resp);
    resp = map_to_coap_error(PT_API_INTERNAL_ERROR);
    CHECK_EQUAL(COAP_RESPONSE_INTERNAL_SERVER_ERROR, resp);
}

TEST(edge_client, test_edgeclient_renew_certificate_success)
{
    int detailed_error = 0;
    mock().expectOneCall("MbedCloudClient::certificate_renew")
            .withStringParameter("cert_name", "test-certificate")
            .andReturnValue(CE_STATUS_SUCCESS);
    pt_api_result_code_e status = edgeclient_renew_certificate("test-certificate", &detailed_error);
    CHECK_EQUAL(PT_API_SUCCESS, status);
    CHECK_EQUAL(CE_STATUS_SUCCESS, detailed_error);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_renew_certificate_error_busy)
{
    int detailed_error = 0;
    mock().expectOneCall("MbedCloudClient::certificate_renew").withStringParameter("cert_name", "test-certificate").andReturnValue(CE_STATUS_DEVICE_BUSY);
    pt_api_result_code_e status = edgeclient_renew_certificate("test-certificate", &detailed_error);
    CHECK_EQUAL(PT_API_CERTIFICATE_RENEWAL_BUSY, status);
    CHECK_EQUAL(CE_STATUS_DEVICE_BUSY, detailed_error);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_renew_certificate_error_generic)
{
    int detailed_error = 0;
    mock().expectOneCall("MbedCloudClient::certificate_renew").withStringParameter("cert_name", "test-certificate").andReturnValue(CE_STATUS_EST_ERROR);
    pt_api_result_code_e status = edgeclient_renew_certificate("test-certificate", &detailed_error);
    CHECK_EQUAL(PT_API_CERTIFICATE_RENEWAL_ERROR, status);
    CHECK_EQUAL(CE_STATUS_EST_ERROR, detailed_error);
    mock().checkExpectations();
}

TEST(edge_client, test_edgeclient_on_certificate_renewal_callback)
{
    mock().expectOneCall("certificate_renewal_notifier_mock")
            .withStringParameter("name", "certificate_name_example")
            .withIntParameter("status", (int) CE_STATUS_SUCCESS)
            .withIntParameter("initiator", (int) CE_INITIATOR_SERVER)
            .withPointerParameter("ctx", (void *) 0x123)
            .andReturnValue(0);

    edgeclient_on_certificate_renewal_callback("certificate_name_example", CE_STATUS_SUCCESS, CE_INITIATOR_SERVER);
}

