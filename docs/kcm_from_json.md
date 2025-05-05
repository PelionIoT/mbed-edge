# Using JSON Configuration to Provision `edge-core` for Izuma Cloud

The `edge-core` daemon now supports provisioning from a structured JSON configuration file using the `--json-conf <path>` CLI option. This feature allows developers and integrators to declaratively define device credentials, configuration, and metadata needed for secure communication with **Izuma Cloud**.

Once the device is provisioned and the Key and Configuration Manager (KCM) is created and stored, the system will **ignore the JSON file on subsequent runs**.

---

## JSON Configuration Format

The JSON file passed via `--json-conf` must follow this structure:

```json
{
  "Certificates": [ ... ],
  "Keys": [ ... ],
  "ConfigParams": [ ... ],
  "SchemeVersion": "0.0.1"
}
```

### Sections

#### 1. `Certificates`

Used to specify DER-encoded X.509 certificates for Bootstrap, LwM2M, and Update services.

```json
{
  "Data": "<file_path_to_der_encoded_certificate>",
  "Format": "der",
  "Name": "mbed.BootstrapDeviceCert"
}
```

Supported certificate names include:

- `mbed.BootstrapDeviceCert`
- `mbed.BootstrapServerCACert`
- `mbed.UpdateAuthCert`
- `mbed.LwM2MDeviceCert`
- `mbed.LwM2MServerCACert`

where, `mbed.BootstrapServerCACert` is Izuma Device Management bootstrap server CA, which is used to sign the bootstrap server certificate. You can retrieve this from the Portal -> Device Identity -> Server -> CA certificate for bootstrap server. Similarly, `mbed.LwM2MServerCACert` is Izuma Device Management LwM2M server CA, which is used to sign the device management server certificate. You can retrieve this from the Portal -> Device Identity -> Server -> CA certificate for LwM2M server.

#### 2. `Keys`

Used to define associated private keys for the device.

```json
{
  "Data": "<file_path_to_der_encoded_private_key>",
  "Format": "der",
  "Name": "mbed.BootstrapDevicePrivateKey",
  "Type": "ECCPrivate"
}
```

Supported key names include:

- `mbed.BootstrapDevicePrivateKey`
- `mbed.LwM2MDevicePrivateKey`

Supported types are: ECCPrivate and ECCPublic

> All certificates and keys must currently be in **DER** format and passed via a **file path**.

#### 3. `ConfigParams`

Used to configure logical settings and metadata, including device identity and LwM2M parameters.

Examples:

```json
{
  "Name": "mbed.UseBootstrap",
  "Data": 0
}
```

Supported keys include:

| Key                        | Description |
|----------------------------|-------------|
| `mbed.UseBootstrap`        | Set to `0` to disable Bootstrap, `1` to enable |
| `mbed.FirstToClaim`        | Optional (0 or 1) |
| `mbed.EndpointName`        | Unique identifier for the device |
| `mbed.LwM2MServerURI`      | Full URI of the LwM2M server (e.g. `coaps://...`) |
| `mbed.BootstrapServerURI`  | Full URI of the Bootstrap server (e.g. `coaps://...`) |
| `mbed.Manufacturer`        | Device manufacturer string |
| `mbed.ModelNumber`         | Model number |
| `mbed.SerialNumber`        | Device serial number |
| `mbed.DeviceType`          | Logical type (e.g., "Sensor", "Edge Gateway") |
| `mbed.HardwareVersion`     | Hardware version string |
| `mbed.MemoryTotalKB`       | Total available memory in KB |
| `mbed.VendorId`            | Hex string (16 bytes) identifying the vendor |
| `mbed.ClassId`             | Hex string (16 bytes) identifying the device class |

> You can add **custom configuration parameters** as well — they will be stored in KCM and can be read later by client applications.

For detailed descriptions of these parameters see [Provisioning Information](https://developer.izumanetworks.com/docs/device-management-provision/1.3/provisioning-info/index.html).

---

## Supported Features

1. **Certificate files in DER format only**
2. **File-based injection** for both Certificates and Keys (no inline data)
3. **Vendor ID and Class ID** must be 16-character hex strings (see [Update auth](https://developer.izumanetworks.com/docs/device-management-provision/1.2/provisioning-info/update-auth-for-firmware-update.html))
4. If `mbed.UseBootstrap` is set to `0`, **Bootstrap configuration is skipped**
5. You may include **custom key-value pairs** in the `ConfigParams` section

---

## Behavior After First Provisioning

Once provisioning is complete and the KCM is written to persistent storage:

- The JSON file will **not be read again**
- To re-apply or update configuration, you must **clear the existing KCM**

---

## Example Usage

1. Example kcm.json

```json
{
    "Certificates": [
        {
            "Data": "/usr/src/app/mbed-edge/edge_configuration/update_dev.cert.der",
            "Format": "der",
            "Name": "mbed.UpdateAuthCert"
        },
        {
            "Data": "/usr/src/app/mbed-edge/edge_configuration/LwM2MDeviceCert.der",
            "Format": "der",
            "Name": "mbed.LwM2MDeviceCert"
        },
        {
            "Data": "/usr/src/app/mbed-edge/edge_configuration/Lwm2mServerCACert.der",
            "Format": "der",
            "Name": "mbed.LwM2MServerCACert"
        }
    ],
    "Keys": [
        {
            "Data": "/usr/src/app/mbed-edge/edge_configuration/LwM2MDevicePrivateKey.der",
            "Format": "der",
            "Name": "mbed.LwM2MDevicePrivateKey",
            "Type": "ECCPrivate"
        }
    ],
    "ConfigParams": [
        {
            "Data": 0,
            "Name": "mbed.UseBootstrap"
        },
        {
            "Name": "mbed.FirstToClaim",
            "Data": 0
        },
        {
            "Data": "01f759b68ace4669874990e4eff9211d",
            "Name": "mbed.EndpointName"
        },
        {
            "Data": "coaps://udp-lwm2m.us-east-1.mbedcloud.com:5684?aid=0192af77b74bb606f785dd2600000000",
            "Name": "mbed.LwM2MServerURI"
        },
        {
            "Data": "Izuma Networks",
            "Name": "mbed.Manufacturer"
        },
        {
            "Data": "IZ-ED-002",
            "Name": "mbed.ModelNumber"
        },
        {
            "Data": "01f759b68ace4669874990e4eff9211d",
            "Name": "mbed.SerialNumber"
        },
        {
            "Data": "Izuma Edge Device",
            "Name": "mbed.DeviceType"
        },
        {
            "Data": "1.0",
            "Name": "mbed.HardwareVersion"
        },
        {
            "Data": 1024,
            "Name": "mbed.MemoryTotalKB"
        },
        {
            "Data": "073a785733384957a0a13ffef6ccf2d9",
            "Name": "mbed.VendorId"
        },
        {
            "Data": "090a41faf2ee48baac4fbd13f2c3eb6f",
            "Name": "mbed.ClassId"
        }
    ],
    "SchemeVersion": "0.0.1"
}
```

2. Build the Docker image

```bash
docker build -t edge-core:byoc-latest -f ./Dockerfile.debian.byoc .
```

3. Run the container with mounted configuration
```bash
docker run -v $PWD/mcc_config:/usr/src/app/mbed-edge/mcc_config \
-v $PWD/edge_configuration:/usr/src/app/mbed-edge/edge_configuration \
edge-core:byoc-latest \
--json-conf /usr/src/app/mbed-edge/edge_configuration/kcm.json
```

where,

* `-v $PWD/mcc_config:/usr/src/app/mbed-edge/mcc_config`: Persists edge-core generated mcc_config (aka KCM) on the host filesystem
* `-v $PWD/edge_configuration:/usr/src/app/mbed-edge/edge_configuration`: Mounts the host directory containing your JSON config along with certificates and keys into the container.
* `--json-conf /usr/src/app/mbed-edge/edge_configuration/kcm.json`: Passes the path to the mounted JSON configuration file as a CLI argument to edge-core.

Ensure that all file paths referenced in the JSON are accessible and has read permissions.