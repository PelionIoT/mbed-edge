// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifdef CERT_ENROLLMENT_EST_MOCK

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "est_defs.h"
#include "pv_log.h"
#include "pv_error_handling.h"
#include "ce_est_mock.h"
#include "ce_crypto_test_utils.h"

/************************************************************************/
/* EST mock classes                                                     */
/************************************************************************/

est_status_e EstClientMock::est_request_enrollment(const char *cert_name,
                                    const size_t cert_name_length,
                                    uint8_t *csr,
                                    const size_t csr_length,
                                    est_enrollment_result_cb result_cb,
                                    void *context) const
{
    bool status;
    est_enrollment_result_e result = EST_ENROLLMENT_SUCCESS;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt *curr_crt_parsed = &crt;
    cert_chain_context_s *cert_chain;
    struct cert_context_s *curr_crt_struct;
    unsigned char *cert_one = NULL;
    size_t cert_one_len = 0;

    SA_PV_LOG_INFO("EST service called for cert %s\n", (char *)cert_name);

    status = create_x509_crt_from_csr(csr, csr_length, curr_crt_parsed);
    if (!status) {
        result_cb(EST_ENROLLMENT_FAILURE, (cert_chain_context_s *)NULL, context);
        return EST_STATUS_SUCCESS;
    }

    // Allocate the chain structure
    cert_chain = (cert_chain_context_s *)malloc(sizeof(cert_chain_context_s));
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cert_chain), result = EST_ENROLLMENT_FAILURE, Exit, "malloc error");

    memset(cert_chain, 0, sizeof(cert_chain_context_s));

    // Set the chain structure initial parameters
    cert_chain->cert_data_context = context;
    cert_chain->chain_length = 0;

    // Allocate the first certificate structure
    cert_chain->certs = (struct cert_context_s*)malloc(sizeof(struct cert_context_s));
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cert_chain->certs), result = EST_ENROLLMENT_FAILURE, Exit, "malloc error");

    memset(cert_chain->certs, 0, sizeof(struct cert_context_s));

    // Set the pointer in the chain structure to point to the first certificate 
    curr_crt_struct = cert_chain->certs;

    while (curr_crt_parsed) {
        // Increment chain length
        cert_chain->chain_length++;
        
        // Fill certificate structure 
        curr_crt_struct->cert_length = (uint16_t)curr_crt_parsed->raw.len;
        curr_crt_struct->cert = (uint8_t *)malloc(curr_crt_struct->cert_length);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((!curr_crt_struct->cert), result = EST_ENROLLMENT_FAILURE, Exit, "malloc error");

        memcpy(curr_crt_struct->cert, curr_crt_parsed->raw.p, curr_crt_struct->cert_length);

        // If not end of chain
        if (curr_crt_parsed->next) {
            // Allocate next certificate structure
            curr_crt_struct->next = (cert_context_s*)malloc(sizeof(cert_context_s));
            SA_PV_ERR_RECOVERABLE_GOTO_IF((!curr_crt_struct->next), result = EST_ENROLLMENT_FAILURE, Exit, "malloc error");

            // Set the current certificate structure to point to the newly allocated next certificate structure
            curr_crt_struct = curr_crt_struct->next;
        }

        curr_crt_parsed = curr_crt_parsed->next;
    }
Exit:
    if (result != EST_ENROLLMENT_SUCCESS) {
        free_cert_chain_context(cert_chain);
    }

    result_cb(result, cert_chain, context);
    mbedtls_x509_crt_free(&crt);
    return EST_STATUS_SUCCESS;
}

void EstClientMock::free_cert_chain_context(cert_chain_context_s *context)
{
    if (context) {
        cert_context_s *next_cert = context->certs;
        while (next_cert != NULL) {
            cert_context_s *temp = next_cert->next;
            free(next_cert->cert);
            free(next_cert);
            next_cert = temp;
        }
        free(context->cert_data_context);
        free(context);
    }
}

#endif // CERT_ENROLLMENT_EST_MOCK
