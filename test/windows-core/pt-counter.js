/* SPDX-License-Identifier: Apache-2.0 */
'use strict';

// JSON-RPC messages follow PelionIoT/mbed-edge-examples/simple-js-examples/
// simple-pt-example.js. Node 22+ supplies WebSocket, so no npm packages are needed.
const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');
const { once } = require('node:events');

async function main() {
    const { values } = parseArgs({ options: {
        url: { type: 'string', default: 'ws://127.0.0.1:7681/1/pt' },
        status: { type: 'string', default: 'http://127.0.0.1:8080/status' },
        output: { type: 'string' },
        device: { type: 'string' },
        initial: { type: 'string', default: '1001' },
        'max-seconds': { type: 'string', default: '1800' },
    } });
    const url = new URL(values.url);
    const statusUrl = new URL(values.status);
    if (url.protocol !== 'ws:' || url.hostname !== '127.0.0.1' || url.pathname !== '/1/pt' ||
        statusUrl.protocol !== 'http:' || statusUrl.hostname !== '127.0.0.1') {
        throw new Error('This test requires the local Windows PT and HTTP status listeners.');
    }
    if (!values.output) throw new Error('--output must name a new evidence directory.');
    const output = path.resolve(values.output);
    const initial = Number(values.initial);
    const maxSeconds = Number(values['max-seconds']);
    if (!Number.isSafeInteger(initial) || !Number.isInteger(maxSeconds) || maxSeconds < 30 || maxSeconds > 3600) {
        throw new Error('Initial counter must be a safe integer; max-seconds must be 30..3600.');
    }
    fs.mkdirSync(output); // Never overwrite evidence from a previous run.
    const runId = new Date().toISOString().replace(/[-:.]/g, '') + '-' + process.pid;
    const deviceId = values.device || 'windows-pt-counter-' + runId;
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(deviceId)) throw new Error('Invalid device name.');
    const resourcePath = '/3300/0/5700';
    const gatewayResourcePath = '/d/' + deviceId + resourcePath;
    const result = {
        schemaVersion: 1, startedUtc: new Date().toISOString(), processId: process.pid,
        nodeVersion: process.version, ptUrl: url.href, deviceId, resourcePath, gatewayResourcePath,
        stage: 'connecting', passed: false, counter: null, updates: [], observations: [],
        deviceUnregistered: false, errors: [],
    };
    const save = () => {
        const temporary = path.join(output, 'result.tmp');
        fs.writeFileSync(temporary, JSON.stringify(result, null, 2) + '\n');
        fs.renameSync(temporary, path.join(output, 'result.json'));
    };
    const event = (kind, detail = {}) => {
        const entry = { utc: new Date().toISOString(), kind, ...detail };
        fs.appendFileSync(path.join(output, 'events.jsonl'), JSON.stringify(entry) + '\n');
        console.log(JSON.stringify(entry));
    };
    const commandsFile = path.join(output, 'commands.jsonl');
    fs.writeFileSync(commandsFile, '');
    save();
    let socket;
    let registered = false;
    let stopping = false;
    let nextId = 0;
    const pending = new Map();
    const rpc = (method, params) => new Promise((resolve, reject) => {
        if (socket.readyState !== WebSocket.OPEN) return reject(new Error('PT connection is closed.'));
        const id = 'counter-' + ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(method + ' timed out.')); }, 15000);
        pending.set(id, { resolve, reject, timer });
        event('rpc-request', { id, method, params });
        socket.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
    const params = counter => {
        // PT numeric values are binary, big endian, then Base64 encoded.
        const bytes = Buffer.alloc(8);
        bytes.writeDoubleBE(counter);
        return { deviceId, objects: [{ objectId: 3300, objectInstances: [{
            objectInstanceId: 0, resources: [{ resourceId: 5700, resourceName: 'Windows PT counter',
                operations: 1, type: 'float', value: bytes.toString('base64') }],
        }] }] };
    };
    const requireOk = async (method, parameters) => {
        const response = await rpc(method, parameters);
        if (response !== 'ok') throw new Error(method + ' returned ' + JSON.stringify(response));
    };
    const cleanup = async reason => {
        if (stopping) return;
        stopping = true;
        result.stage = 'stopping';
        save();
        try {
            if (registered) {
                await requireOk('device_unregister', { deviceId });
                registered = false;
                result.deviceUnregistered = true;
            }
            if (socket && socket.readyState === WebSocket.OPEN) {
                const closed = once(socket, 'close');
                socket.close(1000, 'Test complete');
                await Promise.race([closed, new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('WebSocket close timed out.')), 5000))]);
            }
        } catch (error) { result.errors.push(error.message); }
        result.finishedUtc = new Date().toISOString();
        result.stopReason = reason;
        result.passed = reason === 'complete' && result.deviceUnregistered && result.errors.length === 0 &&
            result.updates.length >= 3 && result.updates.every(update =>
                result.observations.some(observation => observation.updateIndex === update.index));
        result.stage = result.passed ? 'passed' : 'failed';
        save();
        event(result.stage, { reason, cloudChecks: result.observations.length, deviceUnregistered: result.deviceUnregistered });
        process.exit(result.passed ? 0 : 1);
    };
    try {
        const response = await fetch(statusUrl, { signal: AbortSignal.timeout(5000) });
        if (!response.ok) throw new Error('HTTP status request failed: ' + response.status);
        const status = await response.json();
        if (status.status !== 'connected' || !status['internal-id']) throw new Error('Edge Core is not cloud-connected.');
        result.gatewayId = status['internal-id'];
        result.accountId = status['account-id'];
        result.edgeVersion = status['edge-version'];
        socket = new WebSocket(url, 'edge_protocol_translator');
        socket.addEventListener('message', message => {
            try {
                const response = JSON.parse(message.data);
                event('rpc-response', { response });
                if (response.method) {
                    // The counter is read-only: unexpected cloud writes are rejected.
                    if (response.id !== undefined) socket.send(JSON.stringify({ jsonrpc: '2.0', id: response.id,
                        error: { code: -32601, message: 'Read-only counter PT' } }));
                    return;
                }
                const request = pending.get(response.id);
                if (!request) return;
                clearTimeout(request.timer);
                pending.delete(response.id);
                if (response.error) request.reject(new Error(JSON.stringify(response.error)));
                else request.resolve(response.result);
            } catch (error) { result.errors.push(error.message); save(); }
        });
        socket.addEventListener('close', () => {
            for (const request of pending.values()) {
                clearTimeout(request.timer);
                request.reject(new Error('PT connection closed.'));
            }
            pending.clear();
            if (!stopping) {
                result.errors.push('Unexpected PT disconnect.');
                void cleanup('disconnect');
            }
        });
        await Promise.race([once(socket, 'open'), new Promise((_, reject) =>
            setTimeout(() => reject(new Error('WebSocket handshake timed out.')), 10000))]);
        await requireOk('protocol_translator_register', { name: 'windows-counter-' + runId });
        await requireOk('device_register', params(initial));
        registered = true;
        result.counter = initial;
        result.updates.push({ index: 0, value: initial, acknowledgedUtc: new Date().toISOString(), method: 'device_register' });
        result.stage = 'awaiting-cloud-read';
        save();
        event('ready', { gatewayId: result.gatewayId, deviceId, resourcePath, gatewayResourcePath, counter: initial });

        let consumed = 0;
        let busy = false;
        const handle = async command => {
            if (command.action === 'set') {
                if (!Number.isSafeInteger(command.value) || command.value <= result.counter) {
                    throw new Error('Counter must increase to a safe integer.');
                }
                const current = result.updates.at(-1);
                if (!result.observations.some(observation => observation.updateIndex === current.index)) {
                    throw new Error('Verify the current counter in the cloud before changing it.');
                }
                await requireOk('write', params(command.value));
                result.counter = command.value;
                result.updates.push({ index: result.updates.length, value: command.value,
                    acknowledgedUtc: new Date().toISOString(), method: 'write' });
                result.stage = 'awaiting-cloud-read';
                event('counter-changed', { value: command.value });
            } else if (command.action === 'observe') {
                const update = result.updates.at(-1);
                const screenshot = path.resolve(output, command.screenshot || 'missing');
                if (command.gatewayId !== result.gatewayId || command.resourcePath !== gatewayResourcePath ||
                    command.value !== result.counter || !Number.isFinite(Date.parse(command.readStartedUtc)) ||
                    Date.parse(command.readStartedUtc) < Date.parse(update.acknowledgedUtc) ||
                    Date.parse(command.readStartedUtc) > Date.now() ||
                    !screenshot.startsWith(output + path.sep) || !fs.existsSync(screenshot) ||
                    fs.statSync(screenshot).size < 1000 ||
                    result.observations.some(observation => observation.updateIndex === update.index)) {
                    throw new Error('Cloud observation must match the current value, gateway, full resource path, fresh read and a new screenshot in this run.');
                }
                const observation = { updateIndex: update.index, value: command.value, gatewayId: command.gatewayId,
                    resourcePath: command.resourcePath, readStartedUtc: command.readStartedUtc,
                    verifiedUtc: new Date().toISOString(), screenshot: path.relative(output, screenshot), source: 'portal-fresh-read' };
                result.observations.push(observation);
                result.stage = 'cloud-verified';
                event('cloud-verified', observation);
            } else if (command.action === 'stop') {
                await cleanup('complete');
            } else { throw new Error('Unknown command action.'); }
            save();
        };
        setInterval(async () => {
            if (busy || stopping) return;
            busy = true;
            try {
                const lines = fs.readFileSync(commandsFile, 'utf8').split('\n');
                while (consumed < lines.length - 1 && !stopping) {
                    const line = lines[consumed++].trim().replace(/^\uFEFF/, '');
                    if (!line) continue;
                    try { await handle(JSON.parse(line)); }
                    catch (error) { event('command-rejected', { error: error.message }); }
                }
            } catch (error) { result.errors.push(error.message); await cleanup('control-error'); }
            finally { busy = false; }
        }, 250);
        setTimeout(() => { void cleanup('timeout'); }, maxSeconds * 1000);
        process.on('SIGINT', () => { void cleanup('interrupted'); });
        process.on('SIGTERM', () => { void cleanup('interrupted'); });
    } catch (error) {
        result.errors.push(error.message);
        await cleanup('startup-error');
    }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
