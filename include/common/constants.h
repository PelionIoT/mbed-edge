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

#ifndef INCLUDE_COMMON_CONSTANTS_H_
#define INCLUDE_COMMON_CONSTANTS_H_

/**
 * \defgroup EDGE_CONSTANTS Common constants used in Edge Core.
 * @{
 */

/**
 * \file constants.h
 * \brief Common constants used in Edge Core.
 */

/*! *\brief Read operation bitmask for a resource. */
#define OPERATION_READ      0x01
/*! \brief Write operation bitmask for a resource. */
#define OPERATION_WRITE     0x02
/*! \brief Combined read and write operation bitmask for a resource. */
#define OPERATION_READ_WRITE OPERATION_READ | OPERATION_WRITE
/*! \brief Execution operation bitmask for a resource. */
#define OPERATION_EXECUTE   0x04
/*! \brief Delete operation bitmask for a resource. */
#define OPERATION_DELETE    0x08

/**
 * \brief LwM2M resource type enumeration constants.
 */
typedef enum {
    LWM2M_STRING,
    LWM2M_INTEGER,
    LWM2M_FLOAT,
    LWM2M_BOOLEAN,
    LWM2M_OPAQUE,
    LWM2M_TIME,
    LWM2M_OBJLINK
} Lwm2mResourceType;

/**
 * @}
 * Close EDGE_CONSTANTS Doxygen group definition
 */

#endif /* INCLUDE_COMMON_CONSTANTS_H_ */
