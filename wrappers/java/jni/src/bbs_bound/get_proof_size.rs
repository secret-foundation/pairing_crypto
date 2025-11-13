use jni::{objects::JObject, sys::jint, JNIEnv};
use pairing_crypto_c::bbs_bound::get_proof_size::bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_get_proof_size;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_get_1proof_1size(
    _: JNIEnv,
    _: JObject,
    num_undisclosed_messages: jint,
) -> jint {
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_get_proof_size(
        num_undisclosed_messages as usize,
    )
}
