use crate::update_last_error;
use ffi_support::{ByteBuffer, ExternError};
use jni::{
    objects::JObject,
    sys::{jboolean, jbyte, jbyteArray, jint, jlong},
    JNIEnv,
};
use pairing_crypto_c::{
    bbs_bound::{
        proof_gen::{
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_add_message,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_finish,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_init,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_bls_secret_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_presentation_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_public_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_signature,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_verify_signature,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
    },
    dtos::ByteArray,
};

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_init(
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
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1public_1key(
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
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_public_key(
                handle as u64,
                &arr,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1bls_1secret_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    bls_secret_key: jbyteArray,
) -> jint {
    set_array(
        env,
        bls_secret_key,
        Some(BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH),
        |bytes| {
            let mut error = ExternError::success();
            let arr = ByteArray::from(bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_bls_secret_key(
                handle as u64,
                &arr,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    set_array(env, header, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_header(
            handle as u64,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    set_array(env, signature, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        let res = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_signature(
            handle as u64,
            &arr,
            &mut error,
        );
        if res != 0 {
            update_last_error(error.get_message().as_str());
        }
        res
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1presentation_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    presentation_header: jbyteArray,
) -> jint {
    set_array(env, presentation_header, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_presentation_header(
            handle as u64,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1set_1verify_1signature(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
    verify_signature: jboolean,
) -> jint {
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_verify_signature(
        handle as u64,
        verify_signature != 0,
        &mut error,
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    reveal: jboolean,
    message: jbyteArray,
) -> jint {
    set_array(env, message, None, |bytes| {
        let mut error = ExternError::success();
        let arr = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_add_message(
            handle as u64,
            reveal != 0,
            &arr,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_proof_1gen_1context_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut proof_buffer = ByteBuffer::from_vec(vec![]);
    let res = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_finish(
        handle as u64,
        &mut proof_buffer,
        &mut error,
    );
    if res != 0 {
        return res;
    }
    let data = proof_buffer.destroy_into_vec();
    let bytes: Vec<jbyte> = data.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, proof, bytes.as_slice());
    0
}
