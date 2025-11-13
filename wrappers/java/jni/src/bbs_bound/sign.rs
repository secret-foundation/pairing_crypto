use ffi_support::{ByteBuffer, ExternError};
use jni::{
    objects::JObject,
    sys::{jbyte, jbyteArray, jint, jlong},
    JNIEnv,
};
use pairing_crypto_c::{
    bbs_bound::{
        sign::{
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_add_message,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_finish,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_init,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_bls_public_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_header,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_public_key,
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_secret_key,
        },
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
    },
    dtos::ByteArray,
};

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_init(&mut error)
        as jlong
}

fn set_fixed_length_array(
    env: JNIEnv,
    array: jbyteArray,
    expected_len: usize,
    f: impl FnOnce(Vec<u8>) -> jint,
) -> jint {
    match env.convert_byte_array(array) {
        Err(_) => 1,
        Ok(bytes) => {
            if bytes.len() != expected_len {
                2
            } else {
                f(bytes)
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1set_1secret_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    secret_key: jbyteArray,
) -> jint {
    set_fixed_length_array(
        env,
        secret_key,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
        |bytes| {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(&bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_secret_key(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    set_fixed_length_array(
        env,
        public_key,
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        |bytes| {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(&bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_public_key(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1set_1bls_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    bls_public_key: jbyteArray,
) -> jint {
    set_fixed_length_array(
        env,
        bls_public_key,
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
        |bytes| {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(&bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_bls_public_key(
                handle as u64,
                &byte_array,
                &mut error,
            )
        },
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1set_1header(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    header: jbyteArray,
) -> jint {
    match env.convert_byte_array(header) {
        Err(_) => 1,
        Ok(bytes) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(&bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_header(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1add_1message(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(bytes) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(&bytes);
            bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_add_message(
                handle as u64,
                &byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_sign_1context_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut sig = ByteBuffer::from_vec(vec![]);
    let result = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_finish(
        handle as u64,
        &mut sig,
        &mut error,
    );
    if result != 0 {
        return result;
    }
    let sig: Vec<i8> =
        sig.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, signature, sig.as_slice());
    0
}
