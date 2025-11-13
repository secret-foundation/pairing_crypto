use ffi_support::ByteBuffer;
use ffi_support::ExternError;
use jni::objects::JObject;
use jni::sys::{jbyte, jbyteArray, jint};
use jni::JNIEnv;
use pairing_crypto_c::{
    bbs_bound::key_gen::{
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair,
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair,
    },
    dtos::ByteArray,
};

fn generate_key_pair(
    env: JNIEnv,
    ikm: jbyteArray,
    key_info: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
    generator: extern "C" fn(
        ByteArray,
        ByteArray,
        &mut ByteBuffer,
        &mut ByteBuffer,
        &mut ExternError,
    ) -> i32,
) -> jint {
    let ikm = match env.convert_byte_array(ikm) {
        Err(_) => return 1,
        Ok(s) => s,
    };
    let key_info = match env.convert_byte_array(key_info) {
        Err(_) => return 1,
        Ok(s) => s,
    };
    let mut error = ExternError::success();
    let mut sk = ByteBuffer::from_vec(vec![]);
    let mut pk = ByteBuffer::from_vec(vec![]);
    let result = generator(
        ByteArray::from(&ikm),
        ByteArray::from(&key_info),
        &mut sk,
        &mut pk,
        &mut error,
    );
    if result != 0 {
        return result;
    }
    let pk: Vec<i8> = pk.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_generate_1bbs_1key_1pair(
    env: JNIEnv,
    _: JObject,
    ikm: jbyteArray,
    key_info: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    generate_key_pair(
        env,
        ikm,
        key_info,
        public_key,
        secret_key,
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair,
    )
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_pairing_1crypto_Bls12381BbsG1BlsSigG2Sha256_generate_1bls_1key_1pair(
    env: JNIEnv,
    _: JObject,
    ikm: jbyteArray,
    key_info: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    generate_key_pair(
        env,
        ikm,
        key_info,
        public_key,
        secret_key,
        bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair,
    )
}
