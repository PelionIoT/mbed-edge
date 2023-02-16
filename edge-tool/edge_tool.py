#!/usr/bin/env python3

# ----------------------------------------------------------------------------
# Copyright 2018 ARM Ltd.
# Copyright (c) 2023 Izuma Networks
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

# noqa - E501
"""Convert developer certificates to CBOR for runtime injection.

Usage:
  edge_tool.py convert-dev-cert (--development-certificate <path> --cbor <path>) --update-resource <path>
  edge_tool.py add-custom-cert --custom-cert <name> --cbor <path>
  edge_tool.py print-cbor --cbor <path>
  edge_tool.py --help

Options:
  --help                           Show this help.
  --development-certificate path>  The path to Device Management development certificate C source file.
  --update-resource <path>         The path to `update_default_resources.c` source file.
  --cbor <path>                    The CBOR output / input file path.
  --custom-cert <name>             The custom certificate name.
"""

import docopt

from cbor_converter import CBORConverter, CBORUtils


def main():
    args = docopt.docopt(__doc__)
    if args["convert-dev-cert"]:
        converter = CBORConverter(
            args["--development-certificate"],
            args["--update-resource"],
            args["--cbor"],
        )
        converter.convert_to_cbor()
    if args["add-custom-cert"]:
        CBORUtils.add_custom_certificate(args["--cbor"], args["--custom-cert"])
    if args["print-cbor"]:
        CBORUtils.print_cbor(args["--cbor"])


if __name__ == "__main__":
    main()
