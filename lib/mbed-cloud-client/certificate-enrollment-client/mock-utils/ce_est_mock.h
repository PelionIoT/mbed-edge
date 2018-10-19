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


#ifndef __CE_EST_MOCK_H__
#define __CE_EST_MOCK_H__

#ifdef CERT_ENROLLMENT_EST_MOCK


/************************************************************************/
/* EST mock classes                                                     */
/************************************************************************/

class EstClientMock {
public:

    // Use default constructor and destructor

    /**
    * \brief Request certificate enrollment from EST service.
    * \param cert_name, Name of certificate to enroll.
    * \param csr_length, Length of certificate signing request contained wihin csr.
    * \param csr, Buffer containing certificate signing request.
    * \param result_cb, Callback function that is called when EST enrollment finishes.
    * \param context, User context that will be passed to result_cb callback.
    */
    est_status_e est_request_enrollment(const char *cert_name,
                                        const size_t cert_name_length,
                                        uint8_t *csr,
                                        const size_t csr_length,
                                        est_enrollment_result_cb result_cb,
                                        void *context) const;

    static void free_cert_chain_context(cert_chain_context_s *context);


private:
};

#endif // CERT_ENROLLMENT_EST_MOCK


#endif // __CE_EST_MOCK_H__
