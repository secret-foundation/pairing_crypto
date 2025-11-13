use crate::{
    bbs_bound::{
        BbsBoundProofVerifyRequestDto,
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    },
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs_bound::{
    ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::proof_verify as bbs_bound_proof_verify,
    BbsBoundProofVerifyRequest,
};

lazy_static! {
    pub static ref BBS_BOUND_PROOF_VERIFY_CONTEXT: ConcurrentHandleMap<BbsBoundProofVerifyRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_BOUND_PROOF_VERIFY_CONTEXT,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_free
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_BOUND_PROOF_VERIFY_CONTEXT.insert_with_output(err, || {
        BbsBoundProofVerifyRequestDto {
            public_key: Vec::new(),
            header: Vec::new(),
            presentation_header: Vec::new(),
            proof: Vec::new(),
            messages: Vec::new(),
        }
    })
}

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_public_key,
    BBS_BOUND_PROOF_VERIFY_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_header,
    BBS_BOUND_PROOF_VERIFY_CONTEXT,
    header
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_presentation_header,
    BBS_BOUND_PROOF_VERIFY_CONTEXT,
    presentation_header
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_set_proof,
    BBS_BOUND_PROOF_VERIFY_CONTEXT,
    proof
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_add_message(
    handle: u64,
    index: usize,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    BBS_BOUND_PROOF_VERIFY_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.messages.push((index, message));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_verify_context_finish(
    handle: u64,
    err: &mut ExternError,
) -> i32 {
    let result = BBS_BOUND_PROOF_VERIFY_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, PairingCryptoFfiError> {
            let public_key = get_array_value_from_context!(
                ctx.public_key,
                BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
                "public key"
            );

            let header = if ctx.header.is_empty() {
                None
            } else {
                Some(ctx.header.as_slice())
            };

            let presentation_header = if ctx.presentation_header.is_empty() {
                None
            } else {
                Some(ctx.presentation_header.as_slice())
            };

            if ctx.proof.is_empty() {
                return Err(PairingCryptoFfiError::new("proof must be set"));
            }

            let messages = ctx
                .messages
                .iter()
                .map(|(i, m)| (*i, m.as_ref()))
                .collect::<Vec<(usize, &[u8])>>();
            let messages = if messages.is_empty() {
                None
            } else {
                Some(messages.as_slice())
            };

            match bbs_bound_proof_verify(&BbsBoundProofVerifyRequest {
                public_key: &public_key,
                header,
                presentation_header,
                proof: &ctx.proof,
                messages,
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
        if let Err(e) = BBS_BOUND_PROOF_VERIFY_CONTEXT.remove_u64(handle) {
            *err = ExternError::from(e);
        }
    }

    err.get_code().code()
}
