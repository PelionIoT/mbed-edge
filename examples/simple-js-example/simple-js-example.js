/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

const util = require('util')

const JsonRpcWs = require('json-rpc-ws');
const promisify = require('es6-promisify');

const RED    = '\x1b[31m[EdgeJsonRpcExample]\x1b[0m';
const GREEN  = '\x1b[32m[EdgeJsonRpcExample]\x1b[0m';
const YELLOW = '\x1b[33m[EdgeJsonRpcExample]\x1b[0m';

// Timeout time in milliseconds
const TIMEOUT = 10000;

const OPERATIONS = {
    READ       : 0x01,
    WRITE      : 0x02,
    EXECUTE    : 0x04,
    DELETE     : 0x08
};

function EdgeJsonRpcExample() {
    this.name = 'simple-js-example';
    this.api_path = '/1/pt';
    this.socket_path = '/tmp/edge.sock';

    this.client = JsonRpcWs.createClient();
}

EdgeJsonRpcExample.prototype.connect = async function() {
    let self = this;
    return new Promise((resolve, reject) => {
        let url = util.format('ws+unix://%s:%s',
                              this.socket_path,
                              this.api_path);
        console.log(GREEN, 'Connecting to "', url, '"');
        self.client.connect(url,
            function connected(error, reply) {
                if (!error) {
                    resolve(self);
                } else {
                    reject(error);
                }
            });
    });
};

EdgeJsonRpcExample.prototype.disconnect = async function() {
    let self = this;
    return new Promise((resolve, reject) => {
        console.log(GREEN, 'Disconnecting from Mbed Edge.');
        self.client.disconnect((error, response) => {
            if (!error) {
                resolve(response);
            } else {
                reject(error);
            }
        });
    });
};

EdgeJsonRpcExample.prototype.registerProtocolTranslator = async function() {
    let self = this;
    return new Promise((resolve, reject) => {
        let timeout = setTimeout(() => {
            reject('Timeout');
        }, TIMEOUT);

        self.client.send('protocol_translator_register', { 'name': self.name },
            function(error, response) {
                clearTimeout(timeout);
                if (!error) {
                    // Connection ok. Set up to listen for write calls
                    // from Mbed Edge Core.
                    self.exposeWriteMethod();
                    resolve(response);
                } else {
                    reject(error);
                }
            });
    });
};

EdgeJsonRpcExample.prototype._createDeviceParams = function(temperatureValue, setPointValue) {
    // Values are always Base64 encoded strings.
    let temperature = Buffer.allocUnsafe(4);
    temperature.writeFloatBE(temperatureValue)
    temperature = temperature.toString('base64');
    let setPoint = Buffer.allocUnsafe(4);
    setPoint.writeFloatBE(setPointValue);
    setPoint = setPoint.toString('base64');

    // An IPSO/LwM2M temperature sensor and set point sensor (thermostat)
    params = {
        deviceId: 'example-device-1',
        objects: [{
            objectId: 3303,
            objectInstances: [{
                objectInstanceId: 0,
                resources: [{
                    resourceId: 5700,
                    operations: OPERATIONS.READ,
                    type: 'float',
                    value: temperature
                }]
            }]
        }, {
            objectId: 3308,
            objectInstances: [{
                objectInstanceId: 0,
                resources: [{
                    resourceId: 5900,
                    operations: OPERATIONS.READ | OPERATIONS.WRITE,
                    type: 'float',
                    value: setPoint
                }]
            }]
        }]
    };
    return params;
}

EdgeJsonRpcExample.prototype.registerExampleDevice = async function() {
    let self = this;
    return new Promise((resolve, reject) => {

        params = self._createDeviceParams(21.5 /* temp */,
                                         23.5 /* set point */);

        let timeout = setTimeout(() => {
            reject('Timeout');
        }, TIMEOUT);

        self.client.send('device_register', params,
            function(error, response) {
                clearTimeout(timeout);
                if (!error) {
                    resolve(response);
                } else {
                    reject(error);
                }
            });
    });
}

EdgeJsonRpcExample.prototype.unregisterExampleDevice = async function() {
    let self = this;
    return new Promise((resolve, reject) => {
        let timeout = setTimeout(() => {
            reject('Timeout');
        }, TIMEOUT);

        self.client.send('device_unregister', {deviceId: 'example-device-1'},
            function(error, response) {
                clearTimeout(timeout);
                if (!error) {
                    resolve(response);
                } else {
                    reject(error);
                }
            });
    });
}


EdgeJsonRpcExample.prototype.updateExampleDeviceResources = async function() {
    let self = this;
    return new Promise((resolve, reject) => {

        params = self._createDeviceParams(19.5 /* temp */,
                                          20.5 /* set point */);

        let timeout = setTimeout(() => {
            reject('Timeout');
        }, TIMEOUT);

        self.client.send('write', params,
            function(error, response) {
                clearTimeout(timeout);
                if (!error) {
                    resolve(response);
                } else {
                    reject(error);
                }
            });
    });
}

EdgeJsonRpcExample.prototype.exposeWriteMethod = function() {
    let self = this;
    self.client.expose('write', (params, response) => {
        let value = new Buffer.from(params.value, 'base64').readDoubleBE();
        let resourcePath = params.uri.objectId + '/' + params.uri.objectInstanceId
            + '/' + params.uri.resourceId;
        let deviceId = params.uri.deviceId;

        let operation = '';
        if (params.operation === OPERATIONS.WRITE) {
            operation = 'write';
        } else if (params.operation === OPERATIONS.EXECUTE) {
            operation = 'execute';
        } else {
            operation = 'unknown';
        }

        received = {
            deviceId: deviceId,
            resourcePath: resourcePath,
            operation: operation,
            value: value
        }
        console.log(GREEN, 'Received a write method with data:');
        console.log(received);
        console.log(GREEN, 'The raw received JSONRPC 2.0 params:');
        console.log(params);

        /* Always respond back to Mbed Edge, it is expecting
         * an success response to finish the write/execute action.
         * If an error is returned the value write is discarded
         * also in the Mbed Edge Core.
         */
        response(/* no error */ null, /* success */ 'ok');
    });
};

const holdProgress = async (message) => {
    process.stdin.setRawMode(true)
    console.log(YELLOW, util.format('\x1b[1m%s\x1b[0m', message));
    return new Promise(resolve => process.stdin.once('data', () => {
        process.stdin.setRawMode(false);
        resolve();
    }));
}

(async function() {
    try {
        edge = new EdgeJsonRpcExample();

        // Set SIGINT handle
        let quitImmediately = false;
        let sigintHandler;
        process.on('SIGINT', sigintHandler = async function() {
            if (quitImmediately) process.exit(1);
            try {
                await edge.disconnect();
            } catch (ex) {}
            process.exit(1);
        });

        // For waiting user input for example progress
        await holdProgress('Press any key to connect Mbed Edge.');

        await edge.connect();
        console.log(GREEN, 'Connected to Mbed Cloud Edge');

        await holdProgress('Press any key to register as protocol translator.');
        let response = await edge.registerProtocolTranslator();
        console.log(GREEN, 'Registered as protocol translator. Response:', response);

        await holdProgress('Press any key to register the example device.');
        response = await edge.registerExampleDevice();
        console.log(GREEN, 'Registered an example device. Response:', response);

        await holdProgress('Press any key to update example device values.');
        response = await edge.updateExampleDeviceResources();
        console.log(GREEN, 'Updated the resource values. Response:', response);

        await holdProgress('Press any key to unregister the example device.');
        response = await edge.unregisterExampleDevice();
        console.log(GREEN, 'Example device unregistered. Response:', response);

        console.log(GREEN, 'Kill the example with Ctrl+C');
    } catch (ex) {
        try {
            console.error(RED, 'Error...', ex);
            await edge.disconnect();
            process.exit(1);
        } catch (err) {
            console.error(RED, 'Error on closing the Edge Core connection.', err);
            process.exit(1);
        }
    }
})();
