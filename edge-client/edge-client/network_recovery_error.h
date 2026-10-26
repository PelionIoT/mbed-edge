/* SPDX-License-Identifier: Apache-2.0 */
#ifndef EDGE_CLIENT_NETWORK_RECOVERY_ERROR_H
#define EDGE_CLIENT_NETWORK_RECOVERY_ERROR_H
#include "mbed-cloud-client/MbedCloudClient.h"
// Runtime resource/state failures must not permanently disable OS-event recovery.
// Certificate, provisioning and configuration failures keep their existing guard.
inline bool edgeclient_cloud_error_is_recoverable(int code)
{
    return code == MbedCloudClient::ConnectTimeout ||
           code == MbedCloudClient::ConnectNetworkError ||
           code == MbedCloudClient::ConnectDnsResolvingFailed ||
           code == MbedCloudClient::ConnectSecureConnectionFailed ||
           code == MbedCloudClient::ConnectMemoryConnectFail ||
           code == MbedCloudClient::ConnectNotRegistered;
}
#endif
