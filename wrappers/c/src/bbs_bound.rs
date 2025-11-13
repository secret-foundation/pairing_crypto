pub struct BbsBoundSignRequestDto {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub bls_public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

pub struct BbsBoundVerifyRequestDto {
    pub public_key: Vec<u8>,
    pub bls_secret_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

pub struct BbsBoundProofGenRevealMessageRequestDto {
    pub reveal: bool,
    pub value: Vec<u8>,
}

pub struct BbsBoundProofGenRequestDto {
    pub public_key: Vec<u8>,
    pub bls_secret_key: Vec<u8>,
    pub header: Vec<u8>,
    pub messages: Vec<BbsBoundProofGenRevealMessageRequestDto>,
    pub signature: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub verify_signature: Option<bool>,
}

pub struct BbsBoundProofVerifyRequestDto {
    pub public_key: Vec<u8>,
    pub header: Vec<u8>,
    pub presentation_header: Vec<u8>,
    pub proof: Vec<u8>,
    pub messages: Vec<(usize, Vec<u8>)>,
}

pub mod bls_key_pop;
pub mod get_proof_size;
pub mod key_gen;
pub mod proof_gen;
pub mod proof_verify;
pub mod sign;
pub mod verify;

pub use pairing_crypto::bbs::ciphersuites::bls12_381::{
    BBS_BLS12381G1_PUBLIC_KEY_LENGTH,
    BBS_BLS12381G1_SECRET_KEY_LENGTH,
    BBS_BLS12381G1_SIGNATURE_LENGTH,
};

pub use pairing_crypto::bls::ciphersuites::bls12_381::{
    BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
    BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
    BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
};
