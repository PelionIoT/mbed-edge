# Edge tool - A helper tool to observe and manipulate Edge mediated endpoints

The Edge tool can be used during development for retrieving the values from Edge device and Edge mediated endpoints.

## Pre-requisites

Python version 3.4.3+ with SSL support.

The Edge tool depends on [Mbed Cloud SDK](https://cloud.mbed.com/docs/v1.2/mbed-cloud-sdk-python/index.html). It will get installed by the [bootstrap-edge-tool-env.sh](./bootstrap-edge-tool-env.sh) in a virtual environment.

You have to have an account in Mbed Cloud and an API key to access the Mbed Cloud REST API.
For Mbed.

## Configuration

When pre-requisited are satisfied you can create the configuration file for the Mbed Cloud SDK and get access to Mbed Cloud REST API with it.

Create a file with name `.mbed_cloud_config.json` in your `$HOME` or project directory.

```
{
    "api_key": "your_api_key_here"
}
```

### How to run

The entry point for Edge tool is [edge_tool.py](./edge_tool.py).

```
$ ./edge_tool.py -h
```

Mainly the commands takes two parameters `device-id` and `resource-path`. The device identifies can be fetched device listing from Mbed Portal. The field to look for is `Device ID`. It can also be read from Edge device with the status API. The field containing the Device ID is the `internal-id` field.

```
$ curl localhost:8080/status && echo
{"endpoint-name":"<ENDPOINT-NAME>","internal-id":"<DEVICE-ID>","status":"connected"}
```

Resource path is either standard path to resources. For example `/3/0/0` for manufacturer information. See the standard paths from [LWM2M registry](http://www.openmobilealliance.org/wp/OMNA/LwM2M/LwM2MRegistry.html).
The format is `/<OBJECT-ID>/<OBJECT-INSTANCE-ID>/<RESOURCE-ID>`.

Edge device contains also the mediated endpoint resources in the format of `/d/<ENDPOINT-NAME>/3303/0/5700`. The `/d` is fixed prefix to distinguish mediated resource from the Edge device own resources and the `<ENDPOINT-NAME>` is the name supplied by protocol translator for each mediated endpoint.
