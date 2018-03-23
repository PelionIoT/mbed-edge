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

#ifndef EDGE_CORE_CB_H
#define EDGE_CORE_CB_H

#include <stdint.h>
#include "edge-client/edge_client.h"
#include "m2mresource.h"
#include "edge-client/execute_cb_params_base.h"

void edgeserver_execute_resource(edgeclient_request_context_t *request_ctx);

class EdgeCoreCallbackParams: public ExecuteCallbackParamsBase
{
  public:
    EdgeCoreCallbackParams();
    bool set_uri(uint16_t object_id, uint16_t object_instance_id, uint16_t resource_id);

    ~EdgeCoreCallbackParams();

    void execute(void *params);

  private:
    char *uri;
};
#endif
