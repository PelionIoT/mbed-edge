## Device Management Edge API

This is the Doxygen generated API documentation of Device Management Edge.
The API documentation should be used together with the
[Device Management documentation](https://cloud.mbed.com/docs/latest).

The Device Management Edge APIs allow the developers to create protocol translators to adapt
devices that use non-IP based protocols to be managed with Device Management.
These can use for example BacNET, Zigbee, BLE, LoRa or MQTT protocols. Also devices that have
IP connectivity but cannot host full Device Management Client can be adapted with Device Management
Edge API through the protocol translator.

The APIs are implemented in C and some protocol translator examples are in the [mbed-edge-examples repository](https://github.com/ARMmbed/mbed-edge-examples).

The requirements to connect to Device Management are similar between Device Management Edge and
Device Management Client. Please read the [Device Management Client documentation](https://cloud.mbed.com/docs/current/connecting/index.html) to understand
the connectivity of Device Management Edge.

### Device Management Edge components

The main components of the Device Management Edge are:
 * Device Management Client
 * Device Management Edge core
 * Protocol translator API

Device Management Client provides the connectivity to Device Management which Edge core
is extending. Device Management Edge Core implements the specific gateway functionality
and logic. The protocol translator API is used to implement the specific protocol
translator implementation to adapt devices to be managed with Device Management.

The protocol translator communicates with Device Management Edge Core and these components
implements the full adaptation of the devices to be managed.
