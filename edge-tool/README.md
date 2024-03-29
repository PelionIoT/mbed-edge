# Edge tool

It can also be used to convert the development certificate to CBOR configuration object. The development certificate is a C source file which can be downloaded from the [Device Management Portal](https://portal.mbedcloud.com).

The generated CBOR file can be given to Edge Core as command line argument when Edge Core is built with `BYOC_MODE`.

## Pre-requisites

Python version 3.6 or newer with SSL support.

The Edge tool depends on
 * [CBOR2](https://pypi.org/project/cbor2)
 * [PyCLibrary](https://pypi.org/project/pyclibrary)
 * [Cryptography](https://pypi.org/project/cryptography/)

## Install

```
virtualenv edge-tool
source ./edge-tool/bin/activate
python3 setup.py install
```

Please note that Yocto-builds work differently, they do not follow the `requirements.txt`. The Yocto builds bring in the Python-modules via recipes (version specific).

## Run tests

You can run the tests simply with `pytest``.
```
pytest -v
```

### How to run

The entry point for Edge tool is [edge_tool.py](./edge_tool.py).

```
$ ./edge_tool.py -h
```
