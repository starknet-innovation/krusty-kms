//! ElGamal encrypt/decrypt FFI functions.

use std::ffi::c_char;
use std::panic::catch_unwind;

use krusty_kms_common::{ElGamalCiphertext, SecretFelt};
use krusty_kms_crypto::{ElGamal, ElGamalEncryption};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

use crate::error::*;
use crate::helpers::*;
use crate::types::*;

type EncryptFn =
    fn(&Felt, &ProjectivePoint, &Felt, &Felt) -> krusty_kms_common::Result<ElGamalEncryption>;

/// Encrypt a message under an ElGamal public key and produce a proof.
///
/// The proof is serialized as JSON into `out_proof_json`.
///
/// # Atomicity
///
/// Ciphertext points (`out_l` / `out_r`) are written only after the proof
/// buffer write succeeds. On `KMS_ERR_BUFFER_TOO_SMALL`, or when
/// `out_proof_json` is NULL (size probe), the point outputs are left
/// untouched so callers do not observe a partial result.
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
        elgamal_encrypt_inner(
            message,
            public_key,
            random,
            prefix,
            out_l,
            out_r,
            out_proof_json,
            out_proof_json_len,
            out_proof_json_written,
            ElGamal::encrypt,
        )
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

/// Encrypt with the fully transcript-bound Fiat-Shamir proof
/// (`H(prefix, pk, L, R, AL, AR)`).
///
/// Same contract as [`kms_elgamal_encrypt`], but the proof binds the public
/// key and both commitments. Proofs from this entry point are NOT accepted by
/// verifiers pinned to the legacy transcript (deployed Tongo-class Cairo
/// verifiers); use it for off-chain verification or new contracts.
#[no_mangle]
pub unsafe extern "C" fn kms_elgamal_encrypt_strong(
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
        // See kms_elgamal_encrypt: wipe both the plaintext amount and the
        // blinding scalar on every return path.
        elgamal_encrypt_inner(
            message,
            public_key,
            random,
            prefix,
            out_l,
            out_r,
            out_proof_json,
            out_proof_json_len,
            out_proof_json_written,
            ElGamal::encrypt_strong,
        )
    })
    .unwrap_or(KMS_ERR_INTERNAL)
}

#[allow(clippy::too_many_arguments)]
unsafe fn elgamal_encrypt_inner(
    message: *const KmsFelt,
    public_key: *const KmsProjectivePoint,
    random: *const KmsFelt,
    prefix: *const KmsFelt,
    out_l: *mut KmsProjectivePoint,
    out_r: *mut KmsProjectivePoint,
    out_proof_json: *mut c_char,
    out_proof_json_len: usize,
    out_proof_json_written: *mut usize,
    encrypt: EncryptFn,
) -> i32 {
    if message.is_null()
        || public_key.is_null()
        || random.is_null()
        || prefix.is_null()
        || out_l.is_null()
        || out_r.is_null()
    {
        return KMS_ERR_NULL_POINTER;
    }

    // SecretFelt zeroizes on drop (volatile write). Plain Felt copies of the
    // plaintext amount and blinding scalar would linger in stack memory on
    // every path; knowing either reveals the plaintext point (L - pk^r).
    let msg = match kms_to_felt(&*message) {
        Ok(felt) => SecretFelt::new(felt),
        Err(err) => return err.to_status(),
    };
    let pk = match kms_to_proj(&*public_key) {
        Ok(p) => p,
        Err(err) => return err.to_status(),
    };
    let rnd = match kms_to_felt(&*random) {
        Ok(felt) => SecretFelt::new(felt),
        Err(err) => return err.to_status(),
    };
    let pfx = match kms_to_felt(&*prefix) {
        Ok(felt) => felt,
        Err(err) => return err.to_status(),
    };

    let enc = match encrypt(msg.expose_secret(), &pk, rnd.expose_secret(), &pfx) {
        Ok(e) => e,
        Err(_) => return KMS_ERR_CRYPTO,
    };

    let proof_str = match to_deterministic_json(&enc.proof) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let rc = write_string_output(
        &proof_str,
        out_proof_json,
        out_proof_json_len,
        out_proof_json_written,
    );
    if rc != KMS_OK {
        return rc;
    }

    // Size probe (NULL proof buffer): report length only; do not publish points.
    if out_proof_json.is_null() {
        return KMS_OK;
    }

    *out_l = proj_to_kms(&enc.l);
    *out_r = proj_to_kms(&enc.r);
    KMS_OK
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
            Err(err) => return err.to_status(),
        };
        let r = match kms_to_proj(&*ciphertext_r) {
            Ok(p) => p,
            Err(err) => return err.to_status(),
        };
        // SecretFelt zeroizes on drop (volatile write); plain assignment can be DCE'd.
        let sk = match kms_to_felt(&*private_key) {
            Ok(felt) => SecretFelt::new(felt),
            Err(err) => return err.to_status(),
        };

        let cipher = ElGamalCiphertext { l, r };
        match ElGamal::decrypt(&cipher, sk.expose_secret()) {
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
mod tests;
