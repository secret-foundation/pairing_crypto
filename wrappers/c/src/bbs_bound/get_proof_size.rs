use std::convert::TryInto;

use pairing_crypto::bbs_bound::ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::get_proof_size;

/// Return the size of proof in bytes for the bound ciphersuite.
///
/// * num_undisclosed_messages: number of undisclosed messages from original
///   message set
#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_get_proof_size(
    num_undisclosed_messages: usize,
) -> i32 {
    if let Ok(s) = get_proof_size(num_undisclosed_messages).try_into() {
        return s;
    }
    -1
}
