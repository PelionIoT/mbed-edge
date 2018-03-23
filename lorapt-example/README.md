## WISE-3610 LoRa Gateway protocol translator example

<span class="warnings">**Warning:** This is an example to demonstrate the protocol
translator for LoRa endpoints. Do not use for production implementation.</span>

A very simple protocol translator example for the WISE-3610 LoRa Gateway.
The example translates LoRa endpoints (for example WISE-1510) connected to WISE-3610.

### Pre-requisites

- WISE-3610 Gateway device + SDK
- WISE-1510 LoRa endpoint(s) + SDK

### Compilation

Read the `README.md` in the root for configuration instructions.
Read `WISE-3610-SDK/README.md` for compilation instructions for WISE platform.

### Operation description

The protocol translator receives LoRa endpoint information and updates from the
LoRa gateway through the MQTT broker by subscribing to the "LoRa/#" and
"LoRaGw/#" topics. The MQTT messages are handled by the `lorapt_handle_message`
function. 

To simplify the example, only the gateway status messages and endpoint
value messages are handled by the protocol translator although there are stubs for
other message types as well. The example uses a hardcoded protocol translator name
(testing-lora). 

The gateway status message is used to create the protocol
translator instance in the `lorapt_translate_gw_status_message()` function.
The protocol translator will also be implicitly registered if an endpoint value
message is received and the protocol translator is not yet registered. 

Endpoint value messages are handled by `lorapt_translate_node_value_message()` function.
When an endpoint value message is received, the protocol translator checks from a
list whether it has seen the endpoint before or if it is a new one.

New endpoints are registered by calling the `pt_register_device` API and in the
`lorapt_device_register_success_handler` they are added to the list. Seen endpoints
only get their value updated by calling the `pt_write_value` API. Sensor values
(temperature and humidity) are parsed from the value update message and a LwM2M
object is created for each respectively (object ID 3303 for temperature and 
3304 for humidity). A value resource (5700) is created for each object to
hold the sensor value.

### Running

Start edge-core:

```
$ ./edge-core
```

Start the lorapt-example:

```
$ lorapt-example
```

On Mbed Cloud, you should see the LoRa endpoints appear as new devices and they
should have the sensors as resources (temperature as /3303/0/5700 and humidity
as /3304/0/5700).

The lorapt-example supports optional command-line parameters, for example to set the port
and hostname of Edge Core. For help, use:

```
$ lorapt-example --help
```

