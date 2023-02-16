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


def test_no_params():
    """Test with no parameters (success, print help)"""
    ret = os.system("./edge_tool.py")
    assert ret == 256


def test_w_help(tmpdir):
    """Test with no parameters (success, print help)"""
    tmp_outfile = str(tmpdir.join("out"))
    ret = os.system(f"./edge_tool.py --help >{tmp_outfile}")
    assert ret == 0


def test_convert_nonexistent_certs():
    """Test with non-existent folders"""
    ret = os.system(
        "./edge_tool.py convert-dev-cert "
        "--development-certificate /nothing/nowhere.c "
        " --update-resource /nothing/nores.c"
        "--cbor test.cbor"
    )
    # For some reason this does not raise error code
    assert ret == 256


def test_convert_nonexistent_devcert_no_updcert():
    """Test non-existent update cert and no --update-resource given"""
    ret = os.system(
        "./edge_tool.py convert-dev-cert "
        "--development-certificate /nothing/nowhere.c"
        " --cbor dummy.cbor"
    )
    assert ret == 256


'''
// This won't run correctly yet, we get an exception
// Permission error.
def test_convert_certs_to_impossible_destination():
    """Test impossible cbor filename. """
    ret = os.system(
        "./edge_tool.py convert-dev-cert "
        "--development-certificate test_data/mbed_cloud_dev_credentials.c "
        " --update-resource test_data/update_default_resource.c "
        "--cbor /impossible.cbor"
    )
    assert ret != 0
'''
