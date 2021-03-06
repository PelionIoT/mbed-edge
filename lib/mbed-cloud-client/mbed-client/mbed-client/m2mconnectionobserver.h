/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef M2M_CONNECTION_OBSERVER_H__
#define M2M_CONNECTION_OBSERVER_H__

#include "mbed-client/m2minterface.h"

/** \file m2mconnectionobserver.h \brief header for M2MConnectionObserver. */

/** The observer class for passing the socket activity to the state machine. */
class M2MConnectionObserver
{

public :

    /**
      * \enum ServerType, Defines the type of the
      * server that the client wants to use.
      */
    typedef enum {
        Bootstrap,
        LWM2MServer
    }ServerType;

    typedef enum {
        NetworkInterfaceConnected,
        NetworkInterfaceDisconnected
    }NetworkInterfaceStatus;

    /**
     * \brief The M2MSocketAddress struct.
     * A unified container for holding socket address data
     * across different platforms.
     */
    struct SocketAddress{
        M2MInterface::NetworkStack  _stack;
        void                        *_address;
        uint8_t                     _length;
        uint16_t                    _port;
    };

    /**
    * \brief Indicates that data is available from socket.
    * \param data The data read from the socket.
    * \param data_size The length of the data read from the socket.
    * \param address The address of the server where the data is coming from.
    */
    virtual void data_available(uint8_t* data,
                                uint16_t data_size,
                                const M2MConnectionObserver::SocketAddress &address) = 0;

    /**
    * \brief Indicates an error occured in socket.
    * \param error_code The error code from socket, it cannot be used any further.
    * \param retry Indicates whether to re-establish the connection.
    */
    virtual void socket_error(int error_code, bool retry = true) = 0;

    /**
    * \brief Indicates that the server address resolving is ready.
    * \param address The resolved socket address.
    * \param server_type The type of the server.
    * \param server_port The port of the resolved server address.
    */
    virtual void address_ready(const M2MConnectionObserver::SocketAddress &address,
                               M2MConnectionObserver::ServerType server_type,
                               const uint16_t server_port) = 0;

    /**
    * \brief Indicates that data has been sent successfully.
    */
    virtual void data_sent() = 0;

    virtual void network_interface_status_change(NetworkInterfaceStatus status) = 0;
};

#endif // M2M_CONNECTION_OBSERVER_H__
