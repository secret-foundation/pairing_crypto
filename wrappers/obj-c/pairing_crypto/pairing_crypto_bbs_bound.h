#ifndef pairing_crypto_bbs_bound_h
#define pairing_crypto_bbs_bound_h

#include "pairing_crypto_bbs.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair(
    pairing_crypto_byte_buffer_t ikm,
    pairing_crypto_byte_buffer_t key_info,
    pairing_crypto_byte_buffer_t *_Nullable secret_key,
    pairing_crypto_byte_buffer_t *_Nullable public_key,
    pairing_crypto_error_t *_Nullable err);

int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair(
    pairing_crypto_byte_buffer_t ikm,
    pairing_crypto_byte_buffer_t key_info,
    pairing_crypto_byte_buffer_t *_Nullable secret_key,
    pairing_crypto_byte_buffer_t *_Nullable public_key,
    pairing_crypto_error_t *_Nullable err);

int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen(
    const pairing_crypto_byte_buffer_t *_Nonnull bls_secret_key,
    const pairing_crypto_byte_buffer_t *_Nonnull aud,
    const pairing_crypto_byte_buffer_t *_Nonnull dst,
    const pairing_crypto_byte_buffer_t *_Nonnull extra_info,
    pairing_crypto_byte_buffer_t *_Nullable bls_key_pop,
    pairing_crypto_error_t *_Nullable err);

int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify(
    const pairing_crypto_byte_buffer_t *_Nonnull bls_key_pop,
    const pairing_crypto_byte_buffer_t *_Nonnull bls_public_key,
    const pairing_crypto_byte_buffer_t *_Nonnull aud,
    const pairing_crypto_byte_buffer_t *_Nonnull dst,
    const pairing_crypto_byte_buffer_t *_Nonnull extra_info,
    pairing_crypto_error_t *_Nullable err);

uint64_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_init(
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_secret_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_public_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_bls_public_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_add_message(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_finish(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *_Nullable signature,
    pairing_crypto_error_t *_Nullable err);
void bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_free(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);

uint64_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_init(
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_public_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_bls_secret_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_add_message(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_signature(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_finish(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);
void bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_free(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);

uint64_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_init(
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_public_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_bls_secret_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_signature(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_presentation_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_verify_signature(
    uint64_t handle,
    bool verify_signature,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_add_message(
    uint64_t handle,
    bool reveal,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_finish(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *_Nullable proof,
    pairing_crypto_error_t *_Nullable err);
void bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_free(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);

uint64_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_init(
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_public_key(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_presentation_header(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_proof(
    uint64_t handle,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_add_message(
    uint64_t handle,
    uintptr_t index,
    pairing_crypto_byte_buffer_t *value,
    pairing_crypto_error_t *_Nullable err);
int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_finish(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);
void bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_free(
    uint64_t handle,
    pairing_crypto_error_t *_Nullable err);

int32_t bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_get_proof_size(
    uintptr_t num_undisclosed_messages);

#ifdef __cplusplus
}
#endif

#endif /* pairing_crypto_bbs_bound_h */
