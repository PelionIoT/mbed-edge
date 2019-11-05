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

"""Observe and manipulate Edge device values.
   Convert developer certificates to CBOR for runtime injection.

Usage:
  edge_tool.py observe --device-id=<device-id> --resource-path=<resource-path>
  edge_tool.py execute --device-id=<device-id> --resource-path=<resource-path>
  edge_tool.py read    --device-id=<device-id> --resource-path=<resource-path>
  edge_tool.py write   --device-id=<device-id> --resource-path=<resource-path> --new-resource-value=<value>
  edge_tool.py filter  (--host-edge=<device-id> | --edge-devices) [--connected]
  edge_tool.py convert-dev-cert (--development-certificate <path> --cbor <path>) --update-resource <path>
  edge_tool.py add-custom-cert --custom-cert <name> --cbor <path>
  edge_tool.py print-cbor --cbor <path>
  edge_tool.py --help

Options:
  --help                           Show this help.
  --device-id=<device-id>          The id of the device to target.
  --resource-path=<resource-path>  The resource path to target.
  --host-edge=<device-id>          Filter devices hosted by this Edge device.
  --edge-devices                   Filter and list all Edge devices.
  --connected                      Filter only currently connected devices.
  --development-certificate path>  The path to Device Management development certificate C source file.
  --update-resource <path>         The path to `update_default_resources.c` source file.
  --cbor <path>                    The CBOR output / input file path.
  --custom-cert <name>             The custom certificate name.
"""

import sys
import signal
import time
import struct
import docopt
import threading
import traceback
import binascii
import json
from collections import namedtuple

from cloud import observe_async, execute, read, write, \
    filter_edge_devices, filter_edge_hosted_devices

from cbor_converter import CBORConverter, CBORUtils


def main():
    args = docopt.docopt(__doc__)
    device_id = args["--device-id"]
    resource_path = args["--resource-path"]
    if (args["observe"]):
        observe_async(device_id, resource_path)
    if (args["execute"]):
        execute(device_id, resource_path)
    if (args["read"]):
        read(device_id, resource_path)
    if (args["write"]):
        value = args["--new-resource-value"]
        write(device_id, resource_path, value)
    if (args["filter"]):
        if args["--edge-devices"]:
            filter_edge_devices(args["--connected"])
        elif args["--host-edge"]:
            filter_edge_hosted_devices(args["--host-edge"], args["--connected"])
    if (args["convert-dev-cert"]):
        converter = CBORConverter(args["--development-certificate"],
                                  args["--update-resource"],
                                  args["--cbor"])
        converter.convert_to_cbor()
    if (args["add-custom-cert"]):
        CBORUtils.add_custom_certificate(args["--cbor"], args["--custom-cert"])
    if (args["print-cbor"]):
        CBORUtils.print_cbor(args["--cbor"])


if __name__ == "__main__":
    main()
