# Simple Javascript protocol translator example

This example protocol translator show the calls and parameters to pass to
Mbed Edge Core protocol translator API. The websocket connection and
JSONRPC 2.0 specification and communication is left out of the scope to
keep the example simple.

Libraries are used to handle the websocket and JSONRPC 2.0 communication.

Please study the example code to see how to use the protocol translator
JSONRPC 2.0 API and read the relevant documentation for Edge APIs from
[Mbed Cloud Docs](https://cloud.mbed.com/docs/current).

## Dependencies

This example uses `node.js v8` or higher.

Install the dependencies:
```bash
$ npm install
```

Dependencies are:

    simple-js-example
    ├── es6-promisify
    └─┬ json-rpc-ws
      ├─┬ debug
      │ └── ms
      ├── uuid
      └─┬ ws
        ├── async-limiter
        └── safe-buffer

The list with version can be listed with:
```bash
$ npm list
```

## Running

Fixed values for the example:
 * Protocol translator name is `simple-js-example`
 * The device name is `example-device-1`
 * The example device has two LwM2M objects:
   * `3303` which is a temperature sensor and has one readable resource `5700`
   * `3308` which is a set point sensor and has one writable resource `5900`
 * Both resource values are floating point values.

1. Run the Edge Core
   See the pre-requisites to build and run from the root [README.md](./README.md)
1. Verify that Mbed Edge device is connected to Mbed Cloud and visible
   from [Mbed Portal](https://portal.mbedcloud.com)
1. Run this example and connect to Mbed Edge.
   ```bash
   $ nodejs simple-js-example.js
   ```
1. Monitor the registered Edge and endpoint device from Mbed Portal.
