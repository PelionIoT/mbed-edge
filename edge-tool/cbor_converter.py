#!/usr/bin/env python

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

import cbor2
import struct
from pyclibrary import CParser
from collections import namedtuple

CERTIFICATE_KEYS = ('MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE',
                    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE')
KEY_KEYS = ('MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY')

KEY_MAP = {
    'MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE': 'mbed.BootstrapDeviceCert',
    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE': 'mbed.BootstrapServerCACert',
    'MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY': 'mbed.BootstrapDevicePrivateKey',
    'MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME': 'mbed.EndpointName',
    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI': 'mbed.BootstrapServerURI',
    'MBED_CLOUD_DEV_ACCOUNT_ID': 'mbed.AccountId',
    'MBED_CLOUD_DEV_MANUFACTURER': 'mbed.Manufacturer',
    'MBED_CLOUD_DEV_MODEL_NUMBER': 'mbed.ModelNumber',
    'MBED_CLOUD_DEV_SERIAL_NUMBER': 'mbed.SerialNumber',
    'MBED_CLOUD_DEV_DEVICE_TYPE': 'mbed.DeviceType',
    'MBED_CLOUD_DEV_HARDWARE_VERSION': 'mbed.HardwareVersion',
    'MBED_CLOUD_DEV_MEMORY_TOTAL_KB': 'mbed.MemoryTotalKB',
    }

ConfigParam = namedtuple('ConfigParam', ['Data', 'Name'])
Certificate = namedtuple('Certificate', ['Data', 'Format', 'Name'])
Key = namedtuple('Key', ['Data', 'Format', 'Name', 'Type'])

class CBORConverter():

    def __init__(self, development_certificate, cbor_file):
        self.development_certificate = development_certificate
        self.cbor_file = cbor_file


    def parse_c_file(self):
        parser = CParser([self.development_certificate])
        return parser.defs.get('values')


    def create_cbor_data(self, vars):
        cbor_data = {'Certificates': [],
                     'Keys' : [],
                     'ConfigParams': [],
                     'SchemeVersion': '0.0.1'}

        use_bootstrap = 1 if 'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI' in vars.keys() else 0
        cbor_data['ConfigParams'].append(ConfigParam(use_bootstrap, 'mbed.UseBootstrap')._asdict())

        for key in vars.keys():
            var = vars.get(key)
            cbor_var_key = KEY_MAP.get(key, None)
            if cbor_var_key:
                if key in CERTIFICATE_KEYS:
                    byte_data = struct.pack('%sB' % len(var), *var);
                    certificate = Certificate(byte_data, 'der', cbor_var_key)._asdict()
                    cbor_data['Certificates'].append(certificate)
                elif key in KEY_KEYS:
                    byte_data = struct.pack('%sB' % len(var), *var);
                    private_key = Key(byte_data, 'der', cbor_var_key, 'ECCPrivate')._asdict()
                    cbor_data['Keys'].append(private_key)
                else:
                    config_param = ConfigParam(var, cbor_var_key)._asdict()
                    cbor_data['ConfigParams'].append(config_param)
            else:
                print("Key %s not in KEY_MAP." % key)

        return cbor_data


    def convert_to_cbor(self):
        vars = self.parse_c_file()
        cbor_data = self.create_cbor_data(vars)
        with open(self.cbor_file, 'wb') as out_file:
            cbor2.dump(cbor_data, out_file)
