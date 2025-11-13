use crate::dtos::ByteArray;
use ffi_support::{ByteBuffer, ErrorCode, ExternError};
use pairing_crypto::{
    bbs_bound::ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::BbsKeyPair,
    bls::ciphersuites::bls12_381::KeyPair as BlsSigBls12381G2KeyPair,
};

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bbs_key_pair(
    ikm: ByteArray,
    key_info: ByteArray,
    secret_key: &mut ByteBuffer,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    if let Some(key_pair) = BbsKeyPair::new(&ikm.to_vec(), &key_info.to_vec())
    {
        *secret_key =
            ByteBuffer::from_vec(key_pair.secret_key.to_bytes().to_vec());
        *public_key =
            ByteBuffer::from_vec(key_pair.public_key.to_octets().to_vec());
        *err = ExternError::success();
        0
    } else {
        *err = ExternError::new_error(
            ErrorCode::new(1),
            "unexpected failure".to_owned(),
        );
        1
    }
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_generate_bls_key_pair(
    ikm: ByteArray,
    key_info: ByteArray,
    secret_key: &mut ByteBuffer,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    if let Some(key_pair) =
        BlsSigBls12381G2KeyPair::new(&ikm.to_vec(), &key_info.to_vec())
    {
        *secret_key =
            ByteBuffer::from_vec(key_pair.secret_key.to_bytes().to_vec());
        *public_key =
            ByteBuffer::from_vec(key_pair.public_key.to_octets().to_vec());
        *err = ExternError::success();
        0
    } else {
        *err = ExternError::new_error(
            ErrorCode::new(1),
            "unexpected failure".to_owned(),
        );
        1
    }
}
