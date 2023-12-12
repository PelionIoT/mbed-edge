# ----------------------------------------------------------------------------
# Copyright 2021 ARM Ltd.
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

"""edge-tool - convert developer certificates to CBOR for runtime injection."""


import os

from setuptools import setup, find_packages

repository_dir = os.path.dirname(__file__)

with open(os.path.join(repository_dir, "requirements.txt")) as fh:
    requirements = fh.readlines()

setup(
    name="edge-tool",
    version="0.22.0",
    author="DM devops and sre",
    author_email="dmdevopsandsre@izumanetworks.com",
    packages=find_packages(),
    url="https://github.com/PelionIoT/mbed-edge/edge-tool",
    install_requires=requirements,
    python_requires=">=3.6, <3.10",
    license="Apache 2.0",
    description="Tool to convert the development certificates to "
    "CBOR formatted object",
    scripts=["edge_tool.py", "cbor_converter.py"],
)
