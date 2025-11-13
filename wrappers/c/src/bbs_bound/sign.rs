use crate::{
    bbs_bound::{
        BbsBoundSignRequestDto,
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SECRET_KEY_LENGTH,
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
    },
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs_bound::{
    ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::sign as bbs_bound_sign,
    BbsBoundSignRequest,
};

lazy_static! {
    pub static ref BBS_BOUND_SIGN_CONTEXT: ConcurrentHandleMap<BbsBoundSignRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_BOUND_SIGN_CONTEXT,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_free
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_BOUND_SIGN_CONTEXT.insert_with_output(err, || BbsBoundSignRequestDto {
        secret_key: Vec::new(),
        public_key: Vec::new(),
        bls_public_key: Vec::new(),
        header: Vec::new(),
        messages: Vec::new(),
    })
}

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_secret_key,
    BBS_BOUND_SIGN_CONTEXT,
    secret_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_public_key,
    BBS_BOUND_SIGN_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_bls_public_key,
    BBS_BOUND_SIGN_CONTEXT,
    bls_public_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_set_header,
    BBS_BOUND_SIGN_CONTEXT,
    header
);

add_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_add_message,
    BBS_BOUND_SIGN_CONTEXT,
    messages
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_sign_context_finish(
    handle: u64,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sig = BBS_BOUND_SIGN_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
            let secret_key = get_array_value_from_context!(
                ctx.secret_key,
                BBS_BLS12381G1_SECRET_KEY_LENGTH,
                "secret key"
            );

            let public_key = get_array_value_from_context!(
                ctx.public_key,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
                "public key"
            );

            let bls_public_key = get_array_value_from_context!(
                ctx.bls_public_key,
                BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
                "bls public key"
            );

            let header = if ctx.header.is_empty() {
                None
            } else {
                Some(ctx.header.as_slice())
            };

            let messages = ctx
                .messages
                .iter()
                .map(|m| m.as_ref())
                .collect::<Vec<&[u8]>>();
            let messages = if messages.is_empty() {
                None
            } else {
                Some(messages.as_slice())
            };

            let signature_bytes = bbs_bound_sign(&BbsBoundSignRequest {
                secret_key: &secret_key,
                public_key: &public_key,
                bls_public_key: &bls_public_key,
                header,
                messages,
            })?;

            Ok(ByteBuffer::from_vec(signature_bytes.to_vec()))
        },
    );

    if err.get_code().is_success() {
        *signature = sig;
        if let Err(e) = BBS_BOUND_SIGN_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e))
        }
    }

    err.get_code().code()
}
