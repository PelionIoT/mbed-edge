/*
 * ----------------------------------------------------------------------------
 * Copyright 2020 ARM Ltd.
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

#ifdef MBED_EDGE_SUBDEVICE_FOTA

#ifndef EDGE_MANIFEST_OBJECT_H_
#define EDGE_MANIFEST_OBJECT_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MANIFEST_OBJECT 10252
#define DEVICE_META_OBJECT 10255
#define MANIFEST_INSTANCE 0
#define MANIFEST_RESOURCE_PAYLOAD 1
#define MANIFEST_RESOURCE_STATE 2
#define MANIFEST_RESOURCE_RESULT 3
#define MANIFEST_ASSET_HASH 5
#define MANIFEST_VERSION 6
#define xstr(s) str(s)
#define str(s) #s
#define MANIFEST_INFORMATION 10252/0/1

#ifdef __cplusplus
}
#endif

#endif /* EDGE_MANIFEST_OBJECT_H_ */

#endif // MBED_EDGE_SUBDEVICE_FOTA