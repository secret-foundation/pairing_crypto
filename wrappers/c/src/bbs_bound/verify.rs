use crate::{
    bbs_bound::{
        BbsBoundVerifyRequestDto,
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
    },
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs_bound::{
    ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::verify as bbs_bound_verify,
    BbsBoundVerifyRequest,
};

lazy_static! {
    pub static ref BBS_BOUND_VERIFY_CONTEXT: ConcurrentHandleMap<BbsBoundVerifyRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_BOUND_VERIFY_CONTEXT,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_free
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_BOUND_VERIFY_CONTEXT.insert_with_output(err, || BbsBoundVerifyRequestDto {
        public_key: Vec::new(),
        bls_secret_key: Vec::new(),
        header: Vec::new(),
        messages: Vec::new(),
        signature: Vec::new(),
    })
}

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_public_key,
    BBS_BOUND_VERIFY_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_bls_secret_key,
    BBS_BOUND_VERIFY_CONTEXT,
    bls_secret_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_header,
    BBS_BOUND_VERIFY_CONTEXT,
    header
);

add_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_add_message,
    BBS_BOUND_VERIFY_CONTEXT,
    messages
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_set_signature,
    BBS_BOUND_VERIFY_CONTEXT,
    signature
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_verify_context_finish(
    handle: u64,
    err: &mut ExternError,
) -> i32 {
    let result = BBS_BOUND_VERIFY_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, PairingCryptoFfiError> {
            let public_key = get_array_value_from_context!(
                ctx.public_key,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
                "public key"
            );

            let bls_secret_key = get_array_value_from_context!(
                ctx.bls_secret_key,
                BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
                "bls secret key"
            );

            let header = if ctx.header.is_empty() {
                None
            } else {
                Some(ctx.header.as_slice())
            };

            let signature = get_array_value_from_context!(
                ctx.signature,
                BBS_BLS12381G1_SIGNATURE_LENGTH,
                "signature"
            );

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

            match bbs_bound_verify(&BbsBoundVerifyRequest {
                public_key: &public_key,
                bls_secret_key: &bls_secret_key,
                header,
                messages,
                signature: &signature,
            })? {
                true => Ok(0),
                false => Ok(1),
            }
        },
    );

    if err.get_code().is_success() {
        if result != 0 {
            *err = ExternError::new_error(
                ErrorCode::new(1),
                "verification failed",
            );
        }
        if let Err(e) = BBS_BOUND_VERIFY_CONTEXT.remove_u64(handle) {
            *err = ExternError::from(e);
        }
    }

    err.get_code().code()
}
