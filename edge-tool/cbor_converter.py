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

import os
import cbor2
import struct
from pyclibrary import CParser
from collections import namedtuple

CERTIFICATE_KEYS = ('MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE',
                    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE',
                    'arm_uc_default_certificate')

KEY_KEYS = ('MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY')

UPDATE_KEYS = ('arm_uc_default_certificate',
               'arm_uc_class_id',
               'arm_uc_vendor_id')

KEY_MAP = {
    'MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE': 'mbed.BootstrapDeviceCert',
    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE': 'mbed.BootstrapServerCACert',
    'MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY': 'mbed.BootstrapDevicePrivateKey',
    'MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME': 'mbed.EndpointName',
    'MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI': 'mbed.BootstrapServerURI',
    'MBED_CLOUD_DEV_ACCOUNT_ID': 'mbed.AccountID',
    'MBED_CLOUD_DEV_MANUFACTURER': 'mbed.Manufacturer',
    'MBED_CLOUD_DEV_MODEL_NUMBER': 'mbed.ModelNumber',
    'MBED_CLOUD_DEV_SERIAL_NUMBER': 'mbed.SerialNumber',
    'MBED_CLOUD_DEV_DEVICE_TYPE': 'mbed.DeviceType',
    'MBED_CLOUD_DEV_HARDWARE_VERSION': 'mbed.HardwareVersion',
    'MBED_CLOUD_DEV_MEMORY_TOTAL_KB': 'mbed.MemoryTotalKB',
    'arm_uc_default_certificate': 'mbed.UpdateAuthCert',
    'arm_uc_class_id': 'mbed.ClassId',
    'arm_uc_vendor_id': 'mbed.VendorId'
}

ConfigParam = namedtuple('ConfigParam', ['Data', 'Name'])
Certificate = namedtuple('Certificate', ['Data', 'Format', 'Name'])
Key = namedtuple('Key', ['Data', 'Format', 'Name', 'Type'])

class CBORConverter():

    def __init__(self, development_certificate, update_resource, cbor_file):
        self.development_certificate = development_certificate
        self.update_resource = update_resource
        self.cbor_file = cbor_file


    def __check_file_exists(self, path):
        if not os.path.isfile(path):
            print("File '%s' does not exist.")
            return False
        return True

    def parse_c_file(self):
        if not self.__check_file_exists(self.development_certificate) or \
           not self.__check_file_exists(self.update_resource):
            return None

        values = {}
        values.update(CParser([self.development_certificate]).defs.get('values'))
        values.update(CParser([self.update_resource],
                              macros={
                                  'MBED_CLOUD_DEV_UPDATE_ID' : 1,
                                  'MBED_CLOUD_DEV_UPDATE_CERT' : 1
                            }).defs.get('values'))
        return values


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
                elif key in UPDATE_KEYS:
                    byte_data = struct.pack('%sB' % len(var), *var)
                    config_param = ConfigParam(byte_data, cbor_var_key)._asdict()
                    cbor_data['ConfigParams'].append(config_param)
                else:
                    config_param = ConfigParam(var, cbor_var_key)._asdict()
                    cbor_data['ConfigParams'].append(config_param)
            else:
                print("Key %s not in KEY_MAP." % key)

        return cbor_data


    def convert_to_cbor(self):
        vars = self.parse_c_file()
        if not vars:
            print("No variables parsed.")
        else:
            cbor_data = self.create_cbor_data(vars)
            with open(self.cbor_file, 'wb') as out_file:
                cbor2.dump(cbor_data, out_file)
