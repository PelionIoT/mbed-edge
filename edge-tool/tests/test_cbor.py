#!/usr/bin/env python3
#
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

"""Pytest based tests for testing certificate conversion to CBOR."""

import os
import filecmp


def test_cbor_conversion(tmpdir):
    """Test conversion (success)"""
    tmp_outfile = str(tmpdir.join("out.cbor"))
    ret = os.system(
        "./edge_tool.py convert-dev-cert "
        "--development-certificate test_data/mbed_cloud_dev_credentials.c "
        " --update-resource test_data/update_default_resources.c "
        f"--cbor {tmp_outfile}"
    )
    assert ret == 0
    assert filecmp.cmp(tmp_outfile, "test_data/device.cbor", shallow=False)


def test_cbor_print(tmpdir):
    """Test CBOR printing (success)"""
    tmp_outfile = str(tmpdir.join("out.txt"))
    ret = os.system(
        f"./edge_tool.py print-cbor "
        f"--cbor test_data/device.cbor >{tmp_outfile}"
    )
    assert ret == 0
    assert filecmp.cmp(tmp_outfile, "test_data/device.cbor.txt", shallow=False)
