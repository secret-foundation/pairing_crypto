use crate::{
    bbs_bound::{
        BbsBoundProofGenRequestDto,
        BbsBoundProofGenRevealMessageRequestDto,
        BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
        BBS_BLS12381G1_SIGNATURE_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
    },
    dtos::{ByteArray, PairingCryptoFfiError},
};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError};
use pairing_crypto::bbs_bound::{
    ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::proof_gen as bbs_bound_proof_gen,
    BbsBoundProofGenRequest,
    BbsBoundProofGenRevealMessageRequest,
};

lazy_static! {
    pub static ref BBS_BOUND_PROOF_GEN_CONTEXT: ConcurrentHandleMap<BbsBoundProofGenRequestDto> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(
    BBS_BOUND_PROOF_GEN_CONTEXT,
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_free
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_init(
    err: &mut ExternError,
) -> u64 {
    BBS_BOUND_PROOF_GEN_CONTEXT.insert_with_output(err, || {
        BbsBoundProofGenRequestDto {
            public_key: Vec::new(),
            bls_secret_key: Vec::new(),
            header: Vec::new(),
            messages: Vec::new(),
            signature: Vec::new(),
            presentation_header: Vec::new(),
            verify_signature: None,
        }
    })
}

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_public_key,
    BBS_BOUND_PROOF_GEN_CONTEXT,
    public_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_bls_secret_key,
    BBS_BOUND_PROOF_GEN_CONTEXT,
    bls_secret_key
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_header,
    BBS_BOUND_PROOF_GEN_CONTEXT,
    header
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_signature,
    BBS_BOUND_PROOF_GEN_CONTEXT,
    signature
);

set_byte_array_impl!(
    bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_presentation_header,
    BBS_BOUND_PROOF_GEN_CONTEXT,
    presentation_header
);

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_set_verify_signature(
    handle: u64,
    verify_signature: bool,
    err: &mut ExternError,
) -> i32 {
    BBS_BOUND_PROOF_GEN_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.verify_signature = Some(verify_signature);
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_add_message(
    handle: u64,
    reveal: bool,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    BBS_BOUND_PROOF_GEN_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.messages
            .push(BbsBoundProofGenRevealMessageRequestDto { reveal, value: message });
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_proof_gen_context_finish(
    handle: u64,
    proof: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let proof_result = BBS_BOUND_PROOF_GEN_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, PairingCryptoFfiError> {
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

            let presentation_header = if ctx.presentation_header.is_empty() {
                None
            } else {
                Some(ctx.presentation_header.as_slice())
            };

            let messages = ctx
                .messages
                .iter()
                .map(|item| BbsBoundProofGenRevealMessageRequest {
                    reveal: item.reveal,
                    value: item.value.as_ref(),
                })
                .collect::<Vec<BbsBoundProofGenRevealMessageRequest<_>>>();
            let messages = if messages.is_empty() {
                None
            } else {
                Some(messages.as_slice())
            };

            let proof_bytes = bbs_bound_proof_gen(&BbsBoundProofGenRequest {
                public_key: &public_key,
                bls_secret_key: &bls_secret_key,
                header,
                messages,
                signature: &signature,
                presentation_header,
                verify_signature: ctx.verify_signature,
            })?;

            Ok(ByteBuffer::from_vec(proof_bytes))
        },
    );

    if err.get_code().is_success() {
        *proof = proof_result;
        if let Err(e) = BBS_BOUND_PROOF_GEN_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e))
        }
    }

    err.get_code().code()
}
