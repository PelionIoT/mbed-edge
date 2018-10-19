## Mbed Edge API

This is the Doxygen generated API documentation of Mbed Edge.
The API documentation should be used together with the
[Mbed Cloud documentation](https://cloud.mbed.com/docs/latest).

The Mbed Edge APIs allow the developers to create protocol translators to adapt
devices to be managed with Mbed Cloud that use non-IP based protocols.
These can use for example BacNET, Zigbee, BLE, LoRa or MQTT protocols. Also devices that have
IP connectivity but cannot host full Mbed Cloud Client can be adapted with Mbed
Edge API trough the protocol translator.

The APIs are implemented in C and an example protocol translator is contained
within the Mbed Edge repository.

The requirements to connect to Mbed Cloud are similar between Mbed Edge and 
Mbed Cloud Client. Please read the Mbed Cloud Client documentation to understand
the connectivity of Mbed Edge.

### Mbed Edge components

The main components of the Mbed Edge are:
 * Mbed Cloud Client
 * Mbed Edge core
 * Protocol translator API
 
Mbed Cloud Client provides the connectivity to Mbed Cloud which Edge core
is extending. Mbed Edge Core implements the specific gateway functionality
and logic. The protocol translator API is used to implement the specific protocol
translator implementation to adapt devices to be managed with Mbed Cloud.

The protocol translator communicates with Mbed Edge Core and these components
implements the full adaptation of the devices to be managed.
