use crate::dtos::{ByteArray, PairingCryptoFfiError};
use core::convert::TryFrom;
use ffi_support::{ByteBuffer, ExternError};
use pairing_crypto::{
    bbs_bound::{
        ciphersuites::bls12_381_bbs_g1_bls_sig_g2_sha_256::{
            bls_key_pop as bbs_bound_bls_key_pop,
            bls_key_pop_verify as bbs_bound_bls_key_pop_verify,
        },
        BlsKeyPopGenRequest,
        BlsKeyPopVerifyRequest,
    },
    bls::ciphersuites::bls12_381::{
        BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
        BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
    },
};

fn byte_array_to_fixed<const N: usize>(
    value: &ByteArray,
    label: &str,
) -> Result<[u8; N], PairingCryptoFfiError> {
    <[u8; N]>::try_from(value.to_vec()).map_err(|_| {
        PairingCryptoFfiError::new(&format!(
            "{} vector to array conversion failed",
            label
        ))
    })
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_gen(
    bls_secret_key: &ByteArray,
    aud: &ByteArray,
    dst: &ByteArray,
    extra_info: &ByteArray,
    bls_key_pop: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let result = (|| -> Result<ByteBuffer, PairingCryptoFfiError> {
        let secret_key = byte_array_to_fixed::<
            BLS_SIG_BLS12381G2_SECRET_KEY_LENGTH,
        >(bls_secret_key, "bls secret key")?;
        let aud_vec = aud.to_vec();
        let dst_vec = dst.to_vec();
        let extra_vec = extra_info.to_vec();

        let pop = bbs_bound_bls_key_pop(&BlsKeyPopGenRequest {
            bls_secret_key: &secret_key,
            aud: aud_vec.as_slice(),
            dst: if dst_vec.is_empty() {
                None
            } else {
                Some(dst_vec.as_slice())
            },
            extra_info: if extra_vec.is_empty() {
                None
            } else {
                Some(extra_vec.as_slice())
            },
        })?;

        Ok(ByteBuffer::from_vec(pop.to_vec()))
    })();

    match result {
        Ok(pop) => {
            *bls_key_pop = pop;
            *err = ExternError::success();
        }
        Err(e) => {
            *err = ExternError::from(e);
        }
    }

    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_bound_bls12_381_bbs_g1_bls_sig_g2_sha_256_bls_key_pop_verify(
    bls_key_pop: &ByteArray,
    bls_public_key: &ByteArray,
    aud: &ByteArray,
    dst: &ByteArray,
    extra_info: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let result = (|| -> Result<i32, PairingCryptoFfiError> {
        let key_pop = byte_array_to_fixed::<
            BLS_SIG_BLS12381G2_SIGNATURE_LENGTH,
        >(bls_key_pop, "bls key pop")?;
        let public_key = byte_array_to_fixed::<
            BLS_SIG_BLS12381G2_PUBLIC_KEY_LENGTH,
        >(bls_public_key, "bls public key")?;
        let aud_vec = aud.to_vec();
        let dst_vec = dst.to_vec();
        let extra_vec = extra_info.to_vec();

        match bbs_bound_bls_key_pop_verify(&BlsKeyPopVerifyRequest {
            bls_key_pop: &key_pop,
            bls_public_key: &public_key,
            aud: aud_vec.as_slice(),
            dst: if dst_vec.is_empty() {
                None
            } else {
                Some(dst_vec.as_slice())
            },
            extra_info: if extra_vec.is_empty() {
                None
            } else {
                Some(extra_vec.as_slice())
            },
        })? {
            true => Ok(0),
            false => Ok(1),
        }
    })();

    match result {
        Ok(code) => {
            if code != 0 {
                *err = ExternError::from(PairingCryptoFfiError::new(
                    "key pop verification failed",
                ));
            } else {
                *err = ExternError::success();
            }
        }
        Err(e) => {
            *err = ExternError::from(e);
        }
    }

    err.get_code().code()
}
