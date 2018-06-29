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

#include <signal.h>

#include "common/constants.h"
#include "common/integer_length.h"
#include "pt-client/pt_api.h"
#include "pt-client/client.h"
#include "mbed-trace/mbed_trace.h"
#include "pt-example/client_config.h"
#include "pt-example/client_example.h"
#include "ipso_objects.h"
#include "thermal_zone.h"
#include "pt-example/byte_order.h"
#define TRACE_GROUP "clnt-example"
#include "client_example_clip.h"
#include <errno.h>
#include "common/edge_trace.h"
#include <pthread.h>
#include <unistd.h>

#define REAPPEARING_DEVICE "reappearing-thermometer"
#define CPU_TEMPERATURE_DEVICE "cpu-temperature"

pthread_t *reappearing_thread = NULL;
struct reappearing_thread_params *reappearing_params = NULL;

connection_t *g_connection = NULL;

/**
 * \defgroup EDGE_PT_CLIENT_EXAMPLE Protocol translator client example.
 * @{
 */

/**
 * \file client_example.c
 * \brief A usage example of the protocol translator API.
 *
 * This file shows the protocol translator API in use. It describes how to start the protocol
 * translator client and connect it to Mbed Edge.
 * It also shows how the callbacks are used to react to the responses to called remote
 * functions.
 *
 * Note that the protocol translator client is run in event loop, so blocking
 * in the callback handlers blocks the whole protocol translator client
 * from processing any further requests and responses. If there is a long
 * running operation for the responses in the callback handlers, you need
 * to move that work into thread.
 */

/**
 * \brief Flag for the protocol translator example run state
 *
 * 0 if the protocol translator main loop should terminate.\n
 * 1 if the protocol translator main loop should continue.
 */
volatile int keep_running = 1;

/**
 * \brief Flag for the protocol translator example connected
 *
 * false disconnected state
 * true connected state
 */
volatile bool connected = false;

/**
 * \brief Flag for controlling whether the pt-example should unregister the devices when it terminates.
 *        Devices should not be unregistered if the device registrations failed.
 *
 * True if the devices should be unregistered when terminating.\n
 * False if the devices should not be unregistered when terminating.
 */
volatile bool unregister_devices_flag = true;

/**
 * \brief Flag for protocol translator thread state.
 *
 * 0 if the thread is not running.\n
 * 1 if the thread is running.
 */
volatile int protocol_translator_api_running = 0;

/**
 * \brief The thread structure for protocol translator API
 */
pthread_t protocol_translator_api_thread;

/**
 * \brief Structure to pass the protocol translator initialization
 * data to the protocol translator API.
 */
typedef struct protocol_translator_api_start_ctx {
    const char *socket_path;
    char *name;
} protocol_translator_api_start_ctx_t;

static void reappearing_thread_prevent_devices_unregistration(struct reappearing_thread_params *params);
static void unregister_devices();

/**
 * \brief Destroys the reappearing thread parameters
 */
void stop_protocol_translator_api_thread() {
    void *result;
    tr_debug("Waiting for protocol translator api thread to stop.");
    pthread_join(protocol_translator_api_thread, &result);
    protocol_translator_api_running = 0;
}

/**
 * \brief Global device list of known devices for this protocol translator.
 */
pt_device_list_t *_devices = NULL;

/**
 * \brief Find the device by device id from the devices list.
 *
 * \param device_id The device identifier.
 * \return The device if found.\n
 *         NULL is returned if the device is not found.
 */
pt_device_t *find_device(const char* device_id)
{
    ns_list_foreach(pt_device_entry_t, cur, _devices) {
        if (strlen(cur->device->device_id) == strlen(device_id) &&
            strncmp(cur->device->device_id, device_id, strlen(cur->device->device_id)) == 0) {
            return cur->device;
        }
    }
    return NULL;
}

/**
 * \brief Unregisters the test device
 */
static void unregister_devices()
{
    if (unregister_devices_flag) {
        tr_info("Unregistering all devices");
        ns_list_foreach_safe(pt_device_entry_t, cur, _devices)
        {
            pt_status_t status = pt_unregister_device(g_connection,
                                                      cur->device,
                                                      device_unregistration_success,
                                                      device_unregistration_failure,
                                                      /* userdata */ NULL);
            if (PT_STATUS_SUCCESS != status) {
                /* Error happened, remove device forcefully */
                pt_device_free(cur->device);
                ns_list_remove(_devices, cur);
                free(cur);
            }
        }
    }
}

static void shutdown_reappearing_thread()
{
    if (reappearing_params) {
        reappearing_thread_stop();
        destroy_reappearing_device_thread_params(reappearing_params);
        reappearing_params = NULL;
    }
}

static void shutdown_and_cleanup()
{
    shutdown_reappearing_thread();
    unregister_devices();
    while (_devices && ns_list_count(_devices) > 0 && keep_running) {
        sleep(1);
    }
    pt_client_shutdown(g_connection);
    client_config_free();
    keep_running = 0; // Close main thread
}

/**
 * \brief The client example shutdown handler.
 *
 * \param signum The signal number that initiated the shutdown handler.
 */
void shutdown_handler(int signum)
{
    tr_info("Shutdown handler when interrupt %d is received, customer code", signum);

    shutdown_and_cleanup();
}

/**
 * \brief Set up the signal handler for catching signals from OS.
 * This example signal handler setup catches SIGTERM and SIGINT for shutting down
 * the protocol translator client gracefully.
 */
bool setup_signals(void)
{
    struct sigaction sa = { .sa_handler = shutdown_handler, };
    struct sigaction sa_pipe = { .sa_handler = SIG_IGN, };
    int ret_val;

    if (sigemptyset(&sa.sa_mask) != 0) {
        return false;
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        return false;
    }
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        return false;
    }
    ret_val = sigaction(SIGPIPE, &sa_pipe, NULL);
    if (ret_val != 0) {
        tr_warn("setup_signals: sigaction with SIGPIPE returned error=(%d) errno=(%d) strerror=(%s)",
                ret_val,
                errno,
                strerror(errno));
    }
#ifdef DEBUG
    tr_info("Setting support for SIGUSR2");
    if (sigaction(SIGUSR2, &sa, NULL) != 0) {
        return false;
    }
#endif
    return true;
}

/**
 * \brief Value write remote procedure failed callback handler.
 * With this callback, you can react to a failed value write to Mbed Edge.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * to a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_write_value()` call.
 * \param userdata The user-supplied context from the `pt_write_value()` call.
 */
void write_value_failure(const char* device_id, void *userdata)
{
    tr_info("Write value failure for device %s, customer code", device_id);
}

/**
 * \brief Value write remote procedure success callback handler.
 * With this callback, you can react to a successful value write to Mbed Edge.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * to a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_write_value()` call.
 * \param userdata The user-supplied context from the `pt_write_value()` call.
 */
void write_value_success(const char* device_id, void *userdata)
{
    tr_info("Write value success for device %s, customer code", device_id);
}

/**
 * \brief Register the device to Mbed Edge.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param device The device structure for registration.
 * \param success_handler The function to be called when the device registration succeeds
 * \param failure_handler The function to be called when the device registration fails
 * \param handler_param The parameter that is passed to the success or failure handler.
 */
static void register_device(pt_device_t *device,
                            pt_device_response_handler success_handler,
                            pt_device_response_handler failure_handler,
                            void *handler_param)
{
    pt_register_device(g_connection, device, success_handler, failure_handler, handler_param);
}

/**
 * \brief Unregister the device from Mbed Edge. Currently it removes the device resources from Mbed Edge.
 * However, the device still remains in the mbed Cloud.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param device The device to remove.
 */
void unregister_device(pt_device_t *device)
{
    pt_unregister_device(g_connection, device,
                         device_unregistration_success,
                         device_unregistration_failure,
                         (void *) strndup(device->device_id, strlen(device->device_id)));
}

/**
 * \brief Writes a value to device with given device id.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param device_id_string The unique identification of the device.
 * \param temperature The temperature of the device.
 */
void write_value(const char *device_id_string, int temperature)
{
    pt_device_t *device = find_device(device_id_string);
    tr_info("write_value temperature=%d", temperature);
    pt_write_value(g_connection, device, device->objects, write_value_success, write_value_failure, NULL);
}

/**
 * \brief Device registration success callback handler.
 * With this callback, you can react to a successful endpoint device registration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_register_device()` call.
 * \param userdata The user-supplied context from the `pt_register_device()` call.
 */
void device_registration_success(const char* device_id, void *userdata)
{
    tr_info("Device registration successful for '%s', customer code", device_id);

    // FIXME: connected should be set when all the devices have been registered.
    // This prevent the main thread from writing values before the device has been registered.
    // If main thread writes a value before the device is registered, the device registration wil fail
    // causing the application to exit (with current design).
    connected = true;
}

/**
 * \brief Device registration failure callback handler.
 * With this callback, you can react to a failed endpoint device registration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you must move it to
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_register_device()` call.
 * \param userdata The user-supplied context from the `pt_register_device()` call.
 */
void device_registration_failure(const char* device_id, void *userdata)
{
    tr_info("Device registration failure for '%s', customer code", device_id);
    unregister_devices_flag = false;
    if (reappearing_params) {
        reappearing_thread_prevent_devices_unregistration(reappearing_params);
    }
    keep_running = 0;
    shutdown_and_cleanup();
}


#ifdef ENABLE_REAPPEARING_DEVICE
/**
 * \brief Reappearing Device registration success callback handler.
 * In this callback you can react to successful endpoint device registration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_register_device()` call.
 * \param userdata The user supplied context from the pt_register_device() call.
 */
static void reappearing_device_registration_success(const char* device_id, void *userdata)
{
    struct reappearing_thread_params *params = (struct reappearing_thread_params *)userdata;
    tr_info("Device registration successful for '%s', customer code", device_id);
    params->temperature++;
    write_value(device_id, params->temperature);
}
#endif

#ifdef ENABLE_REAPPEARING_DEVICE
/**
 * \brief Reappearing Device registration failure callback handler.
 * In this callback you can react to failed endpoint device registration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_register_device()` call.
 * \param userdata The user supplied context from the `pt_register_device()` call.
 */
static void reappearing_device_registration_failure(const char* device_id, void *userdata)
{
    tr_info("Device registration failed for '%s', customer code", device_id);
    struct reappearing_thread_params *params = (struct reappearing_thread_params *)userdata;
    params->temperature++;
    write_value(device_id, params->temperature);
}
#endif

/**
 * \brief Device unregistration success callback handler.
 * In this callback you can react to successful endpoint device unregistration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_unregister_device()` call.
 * \param userdata The user supplied context from the `pt_unregister_device()` call.
 */
void device_unregistration_success(const char* device_id, void *userdata)
{
    tr_info("Device unregistration successful for '%s', customer code", device_id);
    /* Remove the device from device list and free the allocated memory */
    ns_list_foreach_safe(pt_device_entry_t, cur, _devices) {
        if (strlen(device_id) == strlen(cur->device->device_id) &&
            strncmp(device_id, cur->device->device_id, strlen(device_id)) == 0) {
            pt_device_free(cur->device);
            ns_list_remove(_devices, cur);
            free(cur);
            break;
        }
    }
    free((char*) userdata);
}

/**
 * \brief Device unregistration failure callback handler.
 * In this callback you can react to failed endpoint device unregistration.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param device_id The device id from context from the `pt_unregister_device()` call.
 * \param userdata The user supplied context from the `pt_unregister_device()` call.
 */
void device_unregistration_failure(const char* device_id, void *userdata)
{
    tr_info("Device unregistration failure for '%s', customer code", device_id);
    free((char*) userdata);
}

/**
 * \brief Creates reappearing device thread parameters
 * \param device_name The unique identification of the reappearing device
 * \param visible_time_seconds The time the device will stay visible after appearing.
 * \param hidden_time_seconds The time the device will remain hidden after disappearing.
 */
struct reappearing_thread_params *create_reappearing_device_thread_params(const char *device_name,
                                                                          const char *endpoint_postfix,
                                                                          int visible_time_seconds,
                                                                          int hidden_time_seconds,
                                                                          bool visible)
{
    struct reappearing_thread_params *params = calloc(1, sizeof(struct reappearing_thread_params));
    params->device_name = device_name;
    params->endpoint_postfix = endpoint_postfix;
    params->visible_time_seconds = visible_time_seconds;
    params->hidden_time_seconds = hidden_time_seconds;
    params->visible = visible;
    params->temperature = 200;
    params->sp = NULL;
    params->unregister_devices_flag = true;
    pthread_mutex_init(&params->mutex, NULL);
    return params;
}

/**
 * \brief Stops the reappearing thread and blocks until it finishes.
 */
void reappearing_thread_stop()
{
    pthread_mutex_lock(&reappearing_params->mutex);
    reappearing_params->quit_signal = true;
    pthread_mutex_unlock(&reappearing_params->mutex);
    void *result;
    tr_debug("Waiting for reappearing thread");
    pthread_join(*reappearing_thread, &result);
}

/**
 * \brief Destroys the reappearing thread parameters
 * \param params The parameters to destroy.
 */
void destroy_reappearing_device_thread_params(struct reappearing_thread_params *params)
{
    pthread_mutex_destroy(&params->mutex);
    if (params->sp) {
        free(params->sp);
    }
    free(params);
}

/**
 * \brief returns should the thread exit
 * \param params The parameters of the reappearing thread.
 * \return True if the thread should quit and false if the thread should continue.
 */
bool reappearing_thread_done(struct reappearing_thread_params *params)
{
    bool done;
    pthread_mutex_lock(&params->mutex);
    done = params->quit_signal;
    pthread_mutex_unlock(&params->mutex);
    return done;
}

/**
 * \brief May be called to prevent unregistration of the devices.
 *        Call this, if there's error registering a device. Another pt-example
 *        may be running. We don't want to modify its devices.
 * \param params The parameters of the reappearing thread.
 */
static void reappearing_thread_prevent_devices_unregistration(struct reappearing_thread_params *params)
{
    pthread_mutex_lock(&params->mutex);
    params->unregister_devices_flag = false;
    params->device_registered = false;
    pthread_mutex_unlock(&params->mutex);
}

/**
 * \brief A thread that demonstrates registering and deregistering a device in a continuity.
 * \param args parameters for reappearing thread.
 */
#ifdef ENABLE_REAPPEARING_DEVICE
static void *reappearing_device_thread(void *args)
{
    struct reappearing_thread_params *params = (struct reappearing_thread_params *)args;
    int sleep_amount_in_seconds = 0;
    char *device_id = malloc(strlen(REAPPEARING_DEVICE) + strlen(params->endpoint_postfix) + 1);
    sprintf(device_id, "%s%s", REAPPEARING_DEVICE, params->endpoint_postfix);
    tr_debug("The reappearing thread started");
    while(!reappearing_thread_done(params)) {
        pthread_mutex_lock(&params->mutex);

        if (params->visible) {
            if (params->device_registered && params->unregister_devices_flag) {
                tr_debug("Unregistering the reappearing device");
                pt_device_t *device = find_device(device_id);
                unregister_device(device);
                tr_debug("Unregistering the reappearing device called");
            }
            params->device_registered = false;
            params->visible = false;
            sleep_amount_in_seconds = params->hidden_time_seconds;
        } else {
            if (!params->device_registered && params->unregister_devices_flag) {
                tr_debug("Register the reappearing device");
                pt_device_t *device = client_config_create_reappearing_device(REAPPEARING_DEVICE,
                                                                              params->endpoint_postfix);
                register_device(device,
                                reappearing_device_registration_success,
                                reappearing_device_registration_failure,
                                params);
                client_config_add_device_to_config(_devices, device);
                tr_debug("Register the reappearing device called");
            }
            params->visible = true;
            params->device_registered = true;
            sleep_amount_in_seconds = params->visible_time_seconds;
        }
        pthread_mutex_unlock(&params->mutex);

        while(sleep_amount_in_seconds > 0) {
            tr_debug("Reappearing thread still sleeping for %d seconds.", sleep_amount_in_seconds);
            sleep(1);
            if (params->quit_signal)
                break;
            sleep_amount_in_seconds--;
        }
        params->temperature++;
    }
    pthread_mutex_lock(&params->mutex);
    if (params->device_registered) {
        pt_device_t *device = find_device(device_id);
        tr_debug("Final unregistering of the reappearing device");
        if (device && params->unregister_devices_flag) {
            unregister_device(device);
        }
    }
    pthread_mutex_unlock(&params->mutex);
    tr_debug("Reappearing thread finishes.");
    return NULL;
}
#endif

#ifdef ENABLE_REAPPEARING_DEVICE
/**
 * \brief Creates the reappearing device thread with given parameters.
 * \param params The parameters that configure the functionality of the reappearing device thread.
 * \return pthread_t* The structure that may be used to communicate with the thread.
 */
static pthread_t *create_reappearing_device_thread(struct reappearing_thread_params *params)
{

    reappearing_thread = calloc(1, sizeof(pthread_t));
    pthread_attr_t attr;
    int stack_size = CLIENT_EXAMPLE_REAPPEARING_THREAD_STACK_SIZE;

    if (pthread_attr_init(&attr) != 0) {
        tr_err("Cannot create the reappearing thread attributes");
        goto thread_creation_error;
    }

    if (posix_memalign(&(params->sp), sysconf(_SC_PAGESIZE), stack_size) != 0) {
        tr_err("posix_mem_align returns error");
    }

    if (pthread_attr_setstack(&attr, params->sp, stack_size) != 0) {
        tr_err("cannot set stack for reappearing thread");
    }

    if (pthread_create(reappearing_thread, &attr, reappearing_device_thread, (void *)params)) {
        tr_err("Cannot create the reappearing thread");
        goto thread_creation_error;
    }
    return reappearing_thread;
thread_creation_error:
    free(reappearing_thread);
    reappearing_thread = NULL;
    return NULL;
}
#endif

/**
 * \brief Protocol translator registration success callback handler.
 * With this callback, you can react to a successful protocol translator registration to Mbed Edge.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it
 * to a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param userdata The user-supplied context from the `pt_register_protocol_translator()` call.
 */
void protocol_translator_registration_success(void *userdata)
{
    (void)userdata;
    tr_info("PT registration successful, customer code");
    protocol_translator_api_running = 1;
    /* Register already existing devices from device list */
    ns_list_foreach(pt_device_entry_t, cur, _devices) {
        register_device(cur->device,
                        device_registration_success,
                        device_registration_failure,
                        (void *)cur->device->device_id);
    }
}

/**
 * \brief Protocol translator registration failure callback handler.
 * With this callback, you can react to a failed protocol translator registration to Mbed Edge.
 *
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it to
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param userdata The user-supplied context from the `pt_register_protocol_translator()` call.
 */
void protocol_translator_registration_failure(void *userdata)
{
    tr_info("PT registration failure, customer code");
    unregister_devices_flag = false;
    keep_running = 0;
    shutdown_and_cleanup();
}

/**
 * \brief The implementation of the `pt_connection_ready_cb` function prototype from `pt-client/pt_api.h`.
 *
 * With this callback, you can react to the protocol translator being ready for passing a
 * message with the Mbed Edge Core.
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it to
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param connection The connection which is ready.
 * \param userdata The user supplied context from the `pt_register_protocol_translator()` call.
 */
void connection_ready_handler(connection_t *connection, void *userdata)
{
    /* Initiate protocol translator registration */
    pt_status_t status = pt_register_protocol_translator(
        connection,
        protocol_translator_registration_success,
        protocol_translator_registration_failure,
        userdata);
    if (status != PT_STATUS_SUCCESS) {
        shutdown_and_cleanup();
    }
}

/**
 * \brief The implementation of the `pt_disconnected_cb` function prototype from `pt-client/pt_api.h`.
 *
 * With this callback, you can react to the protocol translator being disconnected from
 * the Mbed Edge Core.
 * The callback runs on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback runs a long process, you need to move it to
 * a worker thread. If the process runs directly in the callback, it
 * blocks the event loop and thus, blocks the protocol translator.
 *
 * \param connection The connection which is disconnected.
 * \param userdata The user supplied context from the `pt_register_protocol_translator()` call.
 */
void disconnected_handler(connection_t *connection, void *userdata)
{
    (void) userdata;
    (void) connection;
    tr_info("Protocol translator got disconnected.");
    connected = false;
}

/**
 * \brief Implementation of `pt_received_write_handle` function prototype handler for
 * write messages received from the Mbed Edge Core.
 *
 * The callback is run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param connection The connection that this write originates from.
 * \param device_id The device id receiving the write.
 * \param object_id The object id of the object receiving the write.
 * \param instance_id The object instance id of the object instance receiving the write.
 * \param resource_id The resource id of the resource receiving the write.
 * \param operation The operation on the resource. See `constants.h` for the defined values.
 * \param value The argument byte buffer of the write operation.
 * \param value_size The size of the value argument.
 * \param userdata* Received userdata from write message.
 *
 * \return Returns 0 on success and non-zero on failure.
 */
int received_write_handler(connection_t* connection,
                           const char *device_id, const uint16_t object_id,
                           const uint16_t instance_id, const uint16_t resource_id,
                           const unsigned int operation,
                           const uint8_t *value, const uint32_t value_size,
                           void* userdata)
{
    tr_info("mbed Cloud Edge write to protocol translator.");

    pt_device_t *device = find_device(device_id);
    pt_object_t *object = pt_device_find_object(device, object_id);
    pt_object_instance_t *instance = pt_object_find_object_instance(object, instance_id);
    const pt_resource_opaque_t *resource = pt_object_instance_find_resource(instance, resource_id);

    if (!device || !object || !instance || !resource) {
        tr_warn("No match for device \"%s/%d/%d/%d\" on write action.",
                device_id, object_id, instance_id, resource_id);
        return 1;
    }

    /* Check if resource supports operation */
    if (!(resource->operations & operation)) {
        tr_warn("Operation %d tried on resource \"%s/%d/%d/%d\" which does not support it.",
                operation, device_id, object_id, instance_id, resource_id);
        return 1;
    }

    if ((operation & OPERATION_WRITE) && resource->callback) {
        tr_info("Writing new value to \"%s/%d/%d/%d\".",
                device_id, object_id, instance_id, resource_id);
        /*
         * The callback must validate the value size to be acceptable.
         * For example, if resource value type is float, the value_size must be acceptable
         * for the float field. And if the resource value type is string the
         * callback may have to reallocate the reserved memory for the new value.
         */
        resource->callback(resource, value, value_size, NULL);
    } else if ((operation & OPERATION_EXECUTE) && resource->callback) {
        resource->callback(resource, value, value_size, NULL);
        /*
         * Update the reset min and max to Edge Core. The Edge Core cannot know the
         * resetted values unless written back.
         */
        pt_write_value(connection, device, device->objects, write_value_success, write_value_failure, (void*) device_id);
    }
    return 0;
}

/**
 * \brief Implementation of the `pt_connection_shutdown_cb` function prototype
 * for shutting down the client application.
 *
 * The callback to be called when the protocol translator client is shutting down. This
 * lets the client application know when the pt-client is shutting down
 * \param connection The connection of the using application.
 * \param userdata The original userdata from the application.
 *
 * \param connection The connection which is closing down.
 * \param userdata The user supplied context from the `pt_register_protocol_translator()` call.
 */
void shutdown_cb_handler(connection_t **connection, void *userdata)
{
    tr_info("Shutting down pt client application, customer code");
    // The connection went away. Main thread can quit now.
    if (keep_running == 0) {
        tr_warn("Already shutting down.");
        return;
    }
    keep_running = 0; // Close main thread
    shutdown_and_cleanup();
}

/**
 * \brief A function to start the protocol translator API.
 *
 * This function is the protocol translator threads main entry point.
 *
 * \param ctx The context object must containt `protocol_translator_api_start_ctx_t` structure
 * to pass the initialization data to protocol translator start function.
 */
void *protocol_translator_api_start_func(void *ctx)
{
    const protocol_translator_api_start_ctx_t *pt_start_ctx = (protocol_translator_api_start_ctx_t*) ctx;

    protocol_translator_callbacks_t pt_cbs;
    pt_cbs.connection_ready_cb = (pt_connection_ready_cb) connection_ready_handler;
    pt_cbs.disconnected_cb = (pt_disconnected_cb) disconnected_handler;
    pt_cbs.received_write_cb = (pt_received_write_handler) received_write_handler;
    pt_cbs.connection_shutdown_cb = (pt_connection_shutdown_cb) shutdown_cb_handler;

    if(0 != pt_client_start(pt_start_ctx->socket_path, pt_start_ctx->name, &pt_cbs, /* userdata */ NULL , &g_connection)) {
        shutdown_reappearing_thread();
        keep_running = 0;
    }
    return NULL;
}

/**
 * \brief Function to create the protocol translator thread.
 *
 * \param ctx The context to pass initialization data to protocol translator API.
 */
void start_protocol_translator_api(protocol_translator_api_start_ctx_t *ctx)
{
    pthread_create(&protocol_translator_api_thread, NULL,
                   &protocol_translator_api_start_func, ctx);
}

/**
 * \brief Update the given temperature to device object
 *
 * This function updates the given temperature to the device object.
 * Internally this function is responsible of changing the given float
 * byte-order to network byte-order. On little endian architecture the
 * byte-order is changed and on big endian architecture the order is unchanged.
 *
 * \param *device The pointer to device object to update
 * \param temperature The temperature in host network byte order.
 */
void update_temperature_to_device(pt_device_t *device, float temperature)
{
    tr_info("Updating temperature to device: %f", temperature);
    pt_object_t *object = pt_device_find_object(device, TEMPERATURE_SENSOR);
    pt_object_instance_t *instance = pt_object_find_object_instance(object, 0);
    pt_resource_opaque_t *resource = pt_object_instance_find_resource(instance, SENSOR_VALUE);

    if (!object || !instance || !resource) {
        tr_err("Could not find the cpu temperature resource.");
        return;
    }

    float current;
    convert_value_to_host_order_float(resource->value, &current);

    /* If value changed update it */
    if (current != temperature) {
        current = temperature; // current value is now the temperature passed in.
        float nw_temperature;
        convert_float_value_to_network_byte_order(temperature,
                                                  (uint8_t*) &nw_temperature);
        /* The value is float, do not change the value_size, original size applies */
        memcpy(resource->value, &nw_temperature, resource->value_size);
    }

    /* Find the min and max resources and update those accordingly
     * Brute force checks, if values are resetted the value changed check
     * for the current value would possibly skip setting the min and max.
     */
    pt_resource_opaque_t *min = pt_object_instance_find_resource(instance, MIN_MEASURED_VALUE);
    if (min) {
        float min_value;
        convert_value_to_host_order_float(min->value, &min_value);
        if (current < min_value) {
            memcpy(min->value, resource->value, resource->value_size);
        }
    }

    pt_resource_opaque_t *max = pt_object_instance_find_resource(instance, MAX_MEASURED_VALUE);
    if (max) {
        float max_value;
        convert_value_to_host_order_float(max->value, &max_value);
        if (current > max_value) {
        memcpy(max->value, resource->value, resource->value_size);
        }
    }
}

void main_loop(DocoptArgs *args)
{
    /* TODO: Implement the enablation of reappearing thread in command line parser
     * Due to current full registration implementation this kills constantly the
     * value observations in Cloud.
     */
    char *cpu_temperature_device_id = malloc(strlen(CPU_TEMPERATURE_DEVICE) + strlen(args->endpoint_postfix) + 1);
    sprintf(cpu_temperature_device_id, "%s%s", CPU_TEMPERATURE_DEVICE, args->endpoint_postfix);

    /* Create reappearing device */
#ifdef ENABLE_REAPPEARING_DEVICE
      const char *reappearing_device_name = REAPPEARING_DEVICE;
      if (reappearing_device_name != NULL && strnlen(reappearing_device_name, 10) > 0) {
          reappearing_params = create_reappearing_device_thread_params(reappearing_device_name,
                                                                       args->endpoint_postfix,
                                                                       10,
                                                                       10,
                                                                       true);
          create_reappearing_device_thread(reappearing_params);
      }
#endif
      pt_device_t *cpu_temperature_device = client_config_create_cpu_temperature_device(CPU_TEMPERATURE_DEVICE,
                                                                                        args->endpoint_postfix);
      if (cpu_temperature_device) {
          client_config_add_device_to_config(_devices, cpu_temperature_device);
    }
    while (keep_running) {
        if (connected) {
            if (find_device(cpu_temperature_device_id) && protocol_translator_api_running) {
                float temperature = tzone_read_cpu_temperature();
                update_temperature_to_device(cpu_temperature_device, temperature);
                pt_write_value(g_connection,
                               cpu_temperature_device,
                               cpu_temperature_device->objects,
                               write_value_success,
                               write_value_failure,
                               cpu_temperature_device->device_id);
            }
        } else {
            tr_debug("main_loop: currently in disconnected state. Not writing any values!");
        }
        sleep(5);
    }
    free(cpu_temperature_device_id);
}

#ifndef BUILD_TYPE_TEST
/**
 * \brief Main entry point to the example application.
 *
 * Mandatory arguments:
 * \li Protocol translator name
 *
 * Optional arguments:
 * \li Endpoint postfix to indicate the running pt-example in device names.
 * \li Edge domain socket path if default path is not used.
 *
 * Starts the protocol translator client and registers the connection ready callback handler.
 *
 * \param argc The number of the command line arguments.
 * \param argv The array of the command line arguments.
 */
int main(int argc, char **argv)
{
    edge_trace_init();
    DocoptArgs args = docopt(argc, argv, /* help */ 1, /* version */ "0.1");

    _devices = client_config_create_device_list(args.endpoint_postfix);

    /* Setup signal handler to catch SIGINT for shutdown */
    if (!setup_signals()) {
        tr_err("Failed to setup signals.\n");
        return 1;
    }

    protocol_translator_api_start_ctx_t *ctx = malloc(sizeof(protocol_translator_api_start_ctx_t));
    if (!args.protocol_translator_name) {
        fprintf(stderr, "The --protocol-translator-name parameter is mandatory. Please see --help\n");
        return 1;
    }
    ctx->name = args.protocol_translator_name;

    ctx->socket_path = args.edge_domain_socket;

    start_protocol_translator_api(ctx);

    main_loop(&args);
    tr_info("Main thread waiting for protocol translator api to stop.");
    // Note: to avoid a leak, we should join the created thread from the same thread it was created from.
    stop_protocol_translator_api_thread();
    free(ctx);
    pt_client_final_cleanup();
    edge_trace_destroy();
}
#endif

/**
 * @}
 * close EDGE_PT_CLIENT_EXAMPLE Doxygen group definition
 */
