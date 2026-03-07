//! ElGamal encrypt/decrypt FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::ElGamal;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

/// Encrypt a message under an ElGamal public key and produce a proof.
///
/// The proof is serialized as JSON into `out_proof_json`.
#[no_mangle]
pub unsafe extern "C" fn kms_elgamal_encrypt(
    message: *const KmsFelt,
    public_key: *const KmsProjectivePoint,
    random: *const KmsFelt,
    prefix: *const KmsFelt,
    out_l: *mut KmsProjectivePoint,
    out_r: *mut KmsProjectivePoint,
    out_proof_json: *mut c_char,
    out_proof_json_len: usize,
    out_proof_json_written: *mut usize,
) -> i32 {
    catch_unwind(|| {
        if message.is_null()
            || public_key.is_null()
            || random.is_null()
            || prefix.is_null()
            || out_l.is_null()
            || out_r.is_null()
        {
            return KMS_ERR_NULL_POINTER;
        }

        let msg = kms_to_felt(&*message);
        let pk = match kms_to_proj(&*public_key) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let rnd = kms_to_felt(&*random);
        let pfx = kms_to_felt(&*prefix);

        let enc = match ElGamal::encrypt(&msg, &pk, &rnd, &pfx) {
            Ok(e) => e,
            Err(_) => return KMS_ERR_CRYPTO,
        };

        *out_l = proj_to_kms(&enc.l);
        *out_r = proj_to_kms(&enc.r);

        let proof_str = match to_deterministic_json(&enc.proof) {
            Ok(s) => s,
            Err(e) => return e,
        };

        write_string_output(
            &proof_str,
            out_proof_json,
            out_proof_json_len,
            out_proof_json_written,
        )
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Decrypt an ElGamal ciphertext, returning the decrypted message point.
#[no_mangle]
pub unsafe extern "C" fn kms_elgamal_decrypt(
    ciphertext_l: *const KmsProjectivePoint,
    ciphertext_r: *const KmsProjectivePoint,
    private_key: *const KmsFelt,
    out_point: *mut KmsProjectivePoint,
) -> i32 {
    catch_unwind(|| {
        if ciphertext_l.is_null()
            || ciphertext_r.is_null()
            || private_key.is_null()
            || out_point.is_null()
        {
            return KMS_ERR_NULL_POINTER;
        }

        let l = match kms_to_proj(&*ciphertext_l) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let r = match kms_to_proj(&*ciphertext_r) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let sk = kms_to_felt(&*private_key);

        let cipher = ElGamalCiphertext { l, r };
        match ElGamal::decrypt(&cipher, &sk) {
            Ok(pt) => {
                *out_point = proj_to_kms(&pt);
                KMS_OK
            }
            Err(_) => KMS_ERR_CRYPTO,
        }
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_crypto::StarkCurve;
    use starknet_types_core::felt::Felt;

    #[test]
    fn test_elgamal_encrypt_decrypt_roundtrip() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let msg_kms = felt_to_kms(&message);
        let pk_kms = proj_to_kms(&pk);
        let rnd_kms = felt_to_kms(&random);
        let pfx_kms = felt_to_kms(&prefix);

        let mut out_l = KmsProjectivePoint {
            x: KmsFelt { bytes: [0; 32] },
            y: KmsFelt { bytes: [0; 32] },
            z: KmsFelt { bytes: [0; 32] },
        };
        let mut out_r = out_l;

        // Two-call pattern: first probe required bytes, then write.
        let mut needed = 0usize;
        let rc = unsafe {
            kms_elgamal_encrypt(
                &msg_kms,
                &pk_kms,
                &rnd_kms,
                &pfx_kms,
                &mut out_l,
                &mut out_r,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        assert_eq!(rc, KMS_OK);
        assert!(needed > 0);

        let mut needed2 = 0usize;
        let rc = unsafe {
            kms_elgamal_encrypt(
                &msg_kms,
                &pk_kms,
                &rnd_kms,
                &pfx_kms,
                &mut out_l,
                &mut out_r,
                std::ptr::null_mut(),
                0,
                &mut needed2,
            )
        };
        assert_eq!(rc, KMS_OK);
        assert_eq!(needed2, needed);

        let mut proof_buf = vec![0u8; needed + 1];
        let mut proof_written = 0usize;
        let rc = unsafe {
            kms_elgamal_encrypt(
                &msg_kms,
                &pk_kms,
                &rnd_kms,
                &pfx_kms,
                &mut out_l,
                &mut out_r,
                proof_buf.as_mut_ptr() as *mut std::ffi::c_char,
                proof_buf.len(),
                &mut proof_written,
            )
        };
        assert_eq!(rc, KMS_OK);
        assert!(proof_written > 0);
        assert_eq!(proof_written, needed);

        // Decrypt
        let sk_kms = felt_to_kms(&sk);
        let mut out_pt = KmsProjectivePoint {
            x: KmsFelt { bytes: [0; 32] },
            y: KmsFelt { bytes: [0; 32] },
            z: KmsFelt { bytes: [0; 32] },
        };
        let rc = unsafe { kms_elgamal_decrypt(&out_l, &out_r, &sk_kms, &mut out_pt) };
        assert_eq!(rc, KMS_OK);

        // Verify decrypted point matches g^message
        let expected = StarkCurve::mul_generator(&message);
        let decrypted = kms_to_proj(&out_pt).unwrap();
        let exp_affine = StarkCurve::projective_to_affine(&expected).unwrap();
        let dec_affine = StarkCurve::projective_to_affine(&decrypted).unwrap();
        assert_eq!(exp_affine, dec_affine);
    }
}
