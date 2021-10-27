#!/usr/bin/env python
# ----------------------------------------------------------------------------
# Copyright 2017-2019 ARM Ltd.
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
import sys
import traceback
import argparse
import hashlib
import textwrap
import binascii

from base64 import b64decode
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import serialization


MBED_DEV_CREDENDIAL_FILENAME = "mbed_cloud_trust_anchor_credentials.c"

class TrustAnchor(object):
   
    def __init__(self, pubkey_pem):
        self.pubkey_der = None
        self.pubkey_name = None
        
        if pubkey_pem is None:
            raise Exception("'pubkey_pem' is None")
        
        pubkey_without_tags = pubkey_pem
        pubkey_without_tags = pubkey_without_tags.replace("-----BEGIN PUBLIC KEY-----", "")
        pubkey_without_tags = pubkey_without_tags.replace("-----END PUBLIC KEY-----", "")
        pubkey_without_tags = textwrap.wrap(pubkey_without_tags, 64)

        self.pubkey_pem = '-----BEGIN PUBLIC KEY-----\n'
        for line in pubkey_without_tags:
            self.pubkey_pem += line + '\n'
        self.pubkey_pem += '-----END PUBLIC KEY-----'

        # Load der public key
        pubkey = serialization.load_pem_public_key(self.pubkey_pem.encode('utf8'), openssl.backend)
        # print key, performs serialization of the DER public key
        encoding = serialization.Encoding["DER"]
        # converts PEM public format to DER format in bytes
        self.pubkey_der = pubkey.public_bytes(encoding=encoding, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.pubkey_name = hashlib.sha256(self.pubkey_der).hexdigest().upper()
        
        self.pubkey_der_hexstring = binascii.hexlify(self.pubkey_der)
		
		# pad with zeros for even digits
        self.pubkey_der_hexstring = self.pubkey_der_hexstring.zfill(len(self.pubkey_der_hexstring) + len(self.pubkey_der_hexstring) % 2)
        
		# split into 2-digit chunks
        self.pubkey_der_hexstring = ', 0x'.join(self.pubkey_der_hexstring[i: i+2] for i in range(0, len(self.pubkey_der_hexstring), 2))
		
		# Add '0x' at the very beginning
        self.pubkey_der_hexstring = '0x' + self.pubkey_der_hexstring
		        
    def create_c_file(self, filename):

        # remove file (which may or may not exist)
        try:
            os.remove(filename)
        except OSError:
            pass

        try:
            self.c_file = open(filename, "wt")
        except Exception as e:
            raise Exception("Cannot open {}".format(c_file))

        #write to c file
        self.c_file.write("// ----------------------------------------------------------------------------\n")
        self.c_file.write("//   The confidential and proprietary information contained in this file may\n")
        self.c_file.write("//   only be used by a person authorized under and to the extent permitted\n")
        self.c_file.write("//   by a subsisting licensing agreement from ARM Limited or its affiliates.\n")
        self.c_file.write("//\n")
        self.c_file.write("//          (C)COPYRIGHT 2018 ARM Limited or its affiliates.\n")
        self.c_file.write("//              ALL RIGHTS RESERVED\n")
        self.c_file.write("//\n")
        self.c_file.write("//   This entire notice must be reproduced on all copies of this file\n")
        self.c_file.write("//   and copies of this file may only be made by a person if such person is\n")
        self.c_file.write("//   permitted to do so under the terms of a subsisting license agreement\n")
        self.c_file.write("//   from ARM Limited or its affiliates.\n")
        self.c_file.write("// ----------------------------------------------------------------------------\n")
        self.c_file.write("\n")
        self.c_file.write("#ifndef __" + filename.replace('.', '_').upper() + "__\n")
        self.c_file.write("#define __" + filename.replace('.', '_').upper() + "__\n")
        self.c_file.write("\n")
        self.c_file.write("#include <inttypes.h>\n")
        self.c_file.write("\n")
        self.c_file.write("const uint8_t MBED_CLOUD_TRUST_ANCHOR_PK[] = {};\n".format("{\n\t" + '\n\t'.join(self.pubkey_der_hexstring[i:i+48] for i in xrange(0, len(self.pubkey_der_hexstring), 48)) + "\n}"))
        self.c_file.write("const uint32_t MBED_CLOUD_TRUST_ANCHOR_PK_SIZE = sizeof(MBED_CLOUD_TRUST_ANCHOR_PK);\n")
        self.c_file.write("\n")
        self.c_file.write("const char MBED_CLOUD_TRUST_ANCHOR_PK_NAME[] = \"mbed.ta.{}\";\n".format(self.pubkey_name))
        self.c_file.write("\n")
        self.c_file.write("#endif // __" + filename.replace('.', '_').upper() + "__\n")
        self.c_file.close()

def parse_arguments():
    parser = argparse.ArgumentParser(description = 'Generates "{}" file that contains the Trust Anchor name and key value (DER format)'.format(MBED_DEV_CREDENDIAL_FILENAME))
    parser.add_argument('-t', '--ta_pem_pubkey', help='Trust Anchor public key in PEM format')
    parser.epilog='Example of use: {} -t "{}"'.format(__file__, "-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbiRnZgdzoBpySFDPVPFp3J7yOmrOXJ09O5qVUMOD5knUjX4YbQVF0ueJWPy6tkTGbzORAwDzvRXYUA7vZpB+og==-----END PUBLIC KEY-----")

    if (len(sys.argv)) != 3:
        parser.print_help()
        exit(1)

    return parser.parse_args()


def main():
    try:        
        args = parse_arguments()
    
        ta = TrustAnchor(args.ta_pem_pubkey)
        
        ta.create_c_file(MBED_DEV_CREDENDIAL_FILENAME)
   
    except Exception, err:
        traceback.print_exc()
        return 1
        
if __name__ == "__main__":
    sys.exit(main())
