use ffi_support::{ByteBuffer, ExternError};
use jni::{
    objects::JObject,
    sys::{jbyte, jbyteArray, jint},
    JNIEnv,
};
use pairing_crypto_c::{
    bbs_bound::bls_key_pop::{
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen,
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify,
    },
    dtos::ByteArray,
};

fn convert_array(env: &JNIEnv, value: jbyteArray) -> Result<Vec<u8>, jint> {
    env.convert_byte_array(value).map_err(|_| 1)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_bls_1key_1pop_1gen(
    env: JNIEnv,
    _: JObject,
    bls_secret_key: jbyteArray,
    aud: jbyteArray,
    dst: jbyteArray,
    extra_info: jbyteArray,
    key_pop: jbyteArray,
) -> jint {
    let bls_secret_key = match convert_array(&env, bls_secret_key) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let aud = match convert_array(&env, aud) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let dst = match convert_array(&env, dst) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let extra = match convert_array(&env, extra_info) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut error = ExternError::success();
    let mut pop = ByteBuffer::from_vec(vec![]);
    let res = bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen(
        &ByteArray::from(&bls_secret_key),
        &ByteArray::from(&aud),
        &ByteArray::from(&dst),
        &ByteArray::from(&extra),
        &mut pop,
        &mut error,
    );
    if res != 0 {
        return res;
    }
    let data = pop.destroy_into_vec();
    let bytes: Vec<jbyte> = data.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, key_pop, bytes.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_bls_1key_1pop_1verify(
    env: JNIEnv,
    _: JObject,
    bls_key_pop: jbyteArray,
    bls_public_key: jbyteArray,
    aud: jbyteArray,
    dst: jbyteArray,
    extra_info: jbyteArray,
) -> jint {
    let bls_key_pop = match convert_array(&env, bls_key_pop) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let bls_public_key = match convert_array(&env, bls_public_key) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let aud = match convert_array(&env, aud) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let dst = match convert_array(&env, dst) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let extra = match convert_array(&env, extra_info) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut error = ExternError::success();
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify(
        &ByteArray::from(&bls_key_pop),
        &ByteArray::from(&bls_public_key),
        &ByteArray::from(&aud),
        &ByteArray::from(&dst),
        &ByteArray::from(&extra),
        &mut error,
    )
}
