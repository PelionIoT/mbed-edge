#!/usr/bin/env python3

# ----------------------------------------------------------------------------
# Copyright 2018 ARM Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

import struct
import signal
import threading
import traceback
import binascii
import json
from collections import namedtuple

from mbed_cloud.connect import ConnectAPI
from mbed_cloud.device_directory import DeviceDirectoryAPI
from mbed_cloud.exceptions import CloudApiException

wait_condition = threading.Condition()
wait_condition.acquire()
keep_running = True

API_connect = ConnectAPI()
API_device_directory = DeviceDirectoryAPI()

def byte_to_hex(value):
    return binascii.hexlify(value)

def byte_to_int(value):
    if len(value) == 2:
        # unsigned short, uint16_t
        return struct.unpack("<H", value)[0]
    elif len(value) == 4:
        # unsigned int, uint32_t
        return struct.unpack("<i", value)[0]
    else:
        return None

def byte_to_float(value):
    return struct.unpack("<f", value)[0]

def byte_to_str(value):
    return value.decode("utf-8")

ResourcePath = namedtuple("ResourcePath", "object_id, instance_id, resource_id")

# See http://www.openmobilealliance.org/wp/OMNA/LwM2M/LwM2MRegistry.html
# Currently Device Management Client supports only text-format for resource values
LWM2M_RESOURCE_MAPPING  = {
#    0: byte_to_str,
#    1: byte_to_str,
#    2: byte_to_str,
#    3: byte_to_str,
#    11: byte_to_int,
#    17: byte_to_str,
#    18: byte_to_str,
#    19: byte_to_str,
#    5700: byte_to_float,
#    5701: byte_to_str,
#    5601: byte_to_float,
#    5602: byte_to_float
}

def red(s):
    if s is None:
        s = "<null>"
    return "\033[91m{}\033[0m".format(s)


def sig_handler(signum, frame):
    print(red("Signal handler called: {}".format(signum)))
    global keep_running
    global wait_condition
    wait_condition.acquire()
    keep_running = False
    wait_condition.notify()
    wait_condition.release()

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

def async_response_is_done(async_resp):
    def check():
        return async_resp.is_done
    return check


def is_keep_running():
    return keep_running


def is_done(async_resp):
    return async_resp.is_done


def split_path(resource_path):
    # remove slash if present in the start
    if resource_path[0] == '/':
        resource_path = resource_path[1:]
    # remove /d if present
    if resource_path.startswith('d/'):
        resource_path = resource_path[3:]
        resource_path = resource_path[(resource_path.index('/') + 1):]

    splitted = resource_path.split('/')
    return ResourcePath(object_id=int(splitted[0]),
                        instance_id=int(splitted[1]),
                        resource_id=int(splitted[2]))

def read(device_id, resource_path):
    API_connect.start_notifications()
    try:
        res = API_connect.get_resource_value(device_id, resource_path)
        print("Read on '{} | {}' completed, value: '{}'".format(device_id, resource_path, res))
    except CloudApiException as e:
        print(red("Exception catched when trying to read"))
        print(red("Reason: {} | status: {} | msg: {}".format(e.reason, e.status, e.message)))

def observe_async(device_id, resource_path):
    global wait_condition
    API_connect.start_notifications()
    devices = API_connect.list_connected_devices().data
    if not devices:
        raise Exception("No devices registered. Aborting")

    current_value = None
    while keep_running:
        try:
            async_resp = API_connect.get_resource_value_async(device_id, resource_path)
        except:
            traceback.print_exc()
            print(red("Get resource value async failed."))
            return

        # Busy wait - block the thread and wait for the response to finish.
        wait_condition.acquire()
        while is_keep_running() and not is_done(async_resp):
            wait_condition.wait(1.0)
        wait_condition.release()

        # Check if we have a async error response, and abort if it is.
        if not async_resp.is_done:
            print("Async response not done, interrupted.")
        elif async_resp.error:
            print(red("Got async error response: {}".format(async_resp.error)))
        else:
            # Get the value from the async response, as we know it's done and it's not
            # an error.
            new_value = async_resp.value

            res = split_path(resource_path)
            new_value = LWM2M_RESOURCE_MAPPING.get(res.resource_id, byte_to_str)(new_value)

            print("New value: {}".format(new_value))
            # Save new current value
            current_value = new_value


def execute(device_id, resource_path):
    API_connect.start_notifications()
    try:
        res = API_connect.execute_resource(device_id, resource_path)
        print("Execute on '{} | {}' returned: '{}'".format(device_id, resource_path, res))
    except CloudApiException as e:
        print(red("Exception catched when trying to execute"))
        print(red("Reason: {} | status: {} | msg: {}".format(e.reason, e.status, e.message)))


KEYS_NEEDED_FOR_DEVICES = ("id", "name", "device_type", "device_execution_mode",
                           "created_at", "updated_at", "state", "account_id",
                           "host_gateway")

def write(device_id, resource_path, value):
    API_connect.start_notifications()
    try:
        res = API_connect.set_resource_value(device_id, resource_path, value)
        print("Write on '{} | {}' completed, new value: '{}'".format(device_id, resource_path, res))
    except CloudApiException as e:
        print(red("Exception catched when trying to write"))
        print(red("Reason: {} | status: {} | msg: {}".format(e.reason, e.status, e.message)))

def device_object_to_dictionary(device):
    return {
        "device-id" : device.id,
        "name": device.name,
        "state": device.state,
        "hosting_edge": device.host_gateway,
        "type": device.device_type,
        "exec_mode": device.device_execution_mode,
        "created_at": device.created_at.isoformat(),
        "updated_at": device.updated_at.isoformat(),
    }


def run_filtered_request(filters, connected):
    if connected:
        devices = API_connect.list_connected_devices(filters=filters).data
    else:
        devices = API_device_directory.list_devices(filters=filters).data

    filtered_devices = []
    for device in devices:
        filtered_devices.append(device_object_to_dictionary(device))
    return filtered_devices


def filter_edge_hosted_devices(edge_device_id, connected):
    edge_host_filter = { "host_gateway": edge_device_id
    }
    filtered_devices = run_filtered_request(edge_host_filter, connected)
    print(json.dumps(filtered_devices, sort_keys=True, indent=2))


def filter_edge_devices(connected):
    edge_filter = { "device_type": "MBED_GW" }
    filtered_devices = run_filtered_request(edge_filter, connected)
    print(json.dumps(filtered_devices, sort_keys=True, indent=2))
