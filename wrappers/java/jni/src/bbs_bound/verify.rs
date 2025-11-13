use ffi_support::ExternError;
use jni::{objects::JObject, sys::{jbyteArray, jint, jlong}, JNIEnv};
use pairing_crypto_c::{
    bbs_bound::{
        verify::{
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_add_message,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_finish,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_init,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_bls_secret_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_public_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_signature,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
    },
    dtos::ByteArray,
};

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_init(&mut error)
        as jlong
}

fn set_array(
    env: JNIEnv,
    value: jbyteArray,
    expected_len: Option<usize>,
    f: impl FnOnce(&[u8]) -> jint,
) -> jint {
    match env.convert_byte_array(value) {
        Err(_) => 1,
        Ok(bytes) => {
            if let Some(len) = expected_len {
                if bytes.len() != len {
                    return 2;
                }
            }
            f(&bytes)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1set_1public_1key(
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
            let byte_array = ByteArray::from(bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_public_key(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1set_1bls_1secret_1key(
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
            let byte_array = ByteArray::from(bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_bls_secret_key(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    set_array(env, header, None, |bytes| {
        let mut error = ExternError::success();
        let byte_array = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_header(
            handle as u64,
            &byte_array,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    set_array(env, message, None, |bytes| {
        let mut error = ExternError::success();
        let byte_array = ByteArray::from(bytes);
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_add_message(
            handle as u64,
            &byte_array,
            &mut error,
        )
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    set_array(
        env,
        signature,
        Some(BBS_BLS12381G1_SIGNATURE_LENGTH),
        |bytes| {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_signature(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_verify_1context_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    let result = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_finish(
        handle as u64,
        &mut error,
    );
    if result != 0 {
        return result;
    }
    error.get_code().code()
}
