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
from six import iteritems, text_type
from pyclibrary import CParser
from collections import namedtuple
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.backends as backends
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
import datetime

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
                    byte_data = struct.pack('%sB' % len(var), *var)
                    certificate = Certificate(byte_data, 'der', cbor_var_key)._asdict()
                    cbor_data['Certificates'].append(certificate)
                elif key in KEY_KEYS:
                    byte_data = struct.pack('%sB' % len(var), *var)
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

class CBORUtils():
    @staticmethod
    def add_custom_certificate(cbor_file, custom_cert_name):
        # Generate EC key pair
        privatekey = ec.generate_private_key(ec.SECP256R1(), backends.default_backend())
        privatebytes = privatekey.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        publickey = privatekey.public_key()
        publicbytes = publickey.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # Create X509 self-signed certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"FI"),
                x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"Oulu"),
                x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Oulu"),
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"ARM"),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, text_type(custom_cert_name))
            ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            publickey
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 1 year
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(privatekey, hashes.SHA256(), backends.default_backend())
        certbytes = cert.public_bytes(serialization.Encoding.DER)

        cbor_data = None
        with open(cbor_file, 'rb') as in_file:
            cbor_data = cbor2.load(in_file)

        privatekey_data = Key(privatebytes, 'der', custom_cert_name, 'ECCPrivate')._asdict()
        publickey_data = Key(publicbytes, 'der', custom_cert_name, 'ECCPublic')._asdict()
        cbor_data['Keys'].append(privatekey_data)
        cbor_data['Keys'].append(publickey_data)
        cert_data = Certificate(certbytes, 'der', custom_cert_name)._asdict()
        cbor_data['Certificates'].append(cert_data)

        with open(cbor_file, 'wb') as out_file:
            cbor2.dump(cbor_data, out_file)

    @staticmethod
    def print_cbor(cbor_file):
        cbor_data = None
        with open(cbor_file, 'rb') as in_file:
            cbor_data = cbor2.load(in_file)

        for k in ['Keys', 'Certificates', 'ConfigParams']:
            v = cbor_data.get(k)
            print(v)
            print(k)
            if v is None:
                continue
            for item in v:
                for kk,vv in iteritems(item):
                    print("\t" + text_type(kk) + " : " + repr(vv))
                print('\t------------------------------')
            print('\r\n')