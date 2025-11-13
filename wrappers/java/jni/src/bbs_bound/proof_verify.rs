use ffi_support::ExternError;
use jni::{objects::JObject, sys::{jbyteArray, jint, jlong}, JNIEnv};
use pairing_crypto_c::{
    bbs_bound::{
        proof_verify::{
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_add_message,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_finish,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_init,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_presentation_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_proof,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_public_key,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    },
    dtos::ByteArray,
};

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_init(
        &mut error,
    ) as jlong
}

fn set_array(
    env: JNIEnv,
    value: jbyteArray,
    expected_len: Option<usize>,
    setter: impl FnOnce(&[u8]) -> jint,
) -> jint {
    match env.convert_byte_array(value) {
        Err(_) => 1,
        Ok(bytes) => {
            if let Some(len) = expected_len {
                if bytes.len() != len {
                    return 2;
                }
            }
            setter(&bytes)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    set_array(
        env,
        public_key,
        Some(BBS_BLS12381G1_PUBLIC_KEY_LENGTH),
        |bytes| {
            let mut error = ExternError::success();
            let arr = ByteArray::from(bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_public_key(
                handle as u64,
                &arr,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    set_array(env, header, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_header(
            handle as u64,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1set_1presentation_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    presentation_header: jbyteArray,
) -> jint {
    set_array(env, presentation_header, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_presentation_header(
            handle as u64,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1set_1proof(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    set_array(env, proof, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_proof(
            handle as u64,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    index: jint,
    message: jbyteArray,
) -> jint {
    set_array(env, message, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_add_message(
            handle as u64,
            index as usize,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1verify_1context_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    let result =
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_finish(
            handle as u64,
            &mut error,
        );
    if result != 0 {
        return result;
    }
    error.get_code().code()
}
