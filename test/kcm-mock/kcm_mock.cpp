#include "CppUTestExt/MockSupport.h"
extern "C" {
#include "key-config-manager/key_config_manager.h"

kcm_status_e kcm_item_get_data_size(const uint8_t *kcm_item_name,
                                    size_t kcm_item_name_len,
                                    kcm_item_type_e kcm_item_type,
                                    size_t *kcm_item_data_size_out)
{
    return (kcm_status_e) mock()
            .actualCall("kcm_item_get_data_size")
            .withStringParameter("kcm_item_data", (char *) kcm_item_name)
            .withIntParameter("kcm_item_name_len", kcm_item_name_len)
            .withIntParameter("kcm_item_type", kcm_item_type)
            .withOutputParameter("kcm_item_data_size_out", kcm_item_data_size_out)
            .returnIntValue();
}

kcm_status_e kcm_item_get_data(const uint8_t *kcm_item_name,
                               size_t kcm_item_name_len,
                               kcm_item_type_e kcm_item_type,
                               uint8_t *kcm_item_data_out,
                               size_t kcm_item_data_max_size,
                               size_t *kcm_item_data_act_size_out)
{
    return (kcm_status_e) mock()
            .actualCall("kcm_item_get_data")
            .withStringParameter("kcm_item_data", (char *) kcm_item_name)
            .withIntParameter("kcm_item_name_len", kcm_item_name_len)
            .withIntParameter("kcm_item_type", kcm_item_type)
            .withOutputParameter("kcm_item_data_out", kcm_item_data_out)
            .withOutputParameter("kcm_item_data_act_size_out", kcm_item_data_act_size_out)
            .returnIntValue();
}


kcm_status_e kcm_generate_random(uint8_t *buffer, size_t buffer_size)
{
    return (kcm_status_e) mock().actualCall("kcm_generate_random")
        .withOutputParameter("buffer", buffer)
        .withUnsignedIntParameter("buffer_size", buffer_size)
        .returnIntValue();
}

kcm_status_e kcm_asymmetric_sign(const uint8_t *private_key_name,
                                 size_t private_key_name_len,
                                 const uint8_t *hash_digest,
                                 size_t hash_digest_size,
                                 uint8_t *signature_data_out,
                                 size_t signature_data_max_size,
                                 size_t *signature_data_act_size_out)
{
    return (kcm_status_e) mock().actualCall("kcm_asymmetric_sign")
        .withMemoryBufferParameter("private_key_name", private_key_name, private_key_name_len)
        .withMemoryBufferParameter("hash_digest", hash_digest, hash_digest_size)
        .withOutputParameter("signature_data_out", signature_data_out)
        .withUnsignedIntParameter("signature_data_max_size", signature_data_max_size)
        .withOutputParameter("signature_data_act_size_out", signature_data_act_size_out)
        .returnIntValue();
}

kcm_status_e kcm_asymmetric_verify(const uint8_t *public_key_name,
                                   size_t public_key_name_len,
                                   const uint8_t *hash_digest,
                                   size_t hash_digest_size,
                                   const uint8_t *signature,
                                   size_t signature_size)
{
    return (kcm_status_e) mock().actualCall("kcm_asymmetric_verify")
        .withMemoryBufferParameter("public_key_name", public_key_name, public_key_name_len)
        .withMemoryBufferParameter("hash_digest", hash_digest, hash_digest_size)
        .withMemoryBufferParameter("signature", signature, signature_size)
        .returnIntValue();
}

#ifndef PARSEC_TPM_SE_SUPPORT
kcm_status_e kcm_ecdh_key_agreement(const uint8_t *private_key_name,
                                    size_t private_key_name_len,
                                    const uint8_t *peer_public_key,
                                    size_t peer_public_key_size,
                                    uint8_t *shared_secret,
                                    size_t shared_secret_max_size,
                                    size_t *shared_secret_act_size_out)
{
    return (kcm_status_e) mock().actualCall("kcm_ecdh_key_agreement")
        .withMemoryBufferParameter("private_key_name", private_key_name, private_key_name_len)
        .withMemoryBufferParameter("peer_public_key", peer_public_key, peer_public_key_size)
        .withOutputParameter("shared_secret", shared_secret)
        .withUnsignedIntParameter("shared_secret_max_size", shared_secret_max_size)
        .withOutputParameter("shared_secret_act_size_out", shared_secret_act_size_out)
        .returnIntValue();
}
#endif // PARSEC_TPM_SE_SUPPORT

} // extern "C"

