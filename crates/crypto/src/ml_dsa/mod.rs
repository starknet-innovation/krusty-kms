//! ML-DSA-65 (FIPS 204) public-key expansion and the felt payload the Cairo
//! account verifier consumes.
//!
//! # What this is for
//!
//! A Starknet account contract whose signing key is post-quantum cannot afford
//! to recompute FIPS 204 verification on chain. Instead the signer sends the
//! result — the matrix product `w` — alongside two quotient witnesses `M'` and
//! `K'` that assert the relation as an exact identity of integer polynomials:
//!
//! ```text
//! A.z - c.T  =  w  +  Q*M'  +  (X^256 + 1)*K'
//! ```
//!
//! The contract checks that identity at one random point. This module is the
//! off-chain half: it verifies the signature properly, and emits the 1,830-felt
//! payload the contract needs to be convinced of it.
//!
//! # Why the math is here and not in a library
//!
//! No published Rust ML-DSA crate can serve this. `ml-dsa`, `fips204`,
//! `libcrux-ml-dsa` and the PQClean bindings all expose only keygen, sign and
//! verify; the NTT, `ExpandA`, `SampleInBall` and bit-unpacking are private in
//! every one. The payload above *is* the verification transcript — the `w` rows
//! the hints commit to must be the exact ones the verifier computed — so a
//! `verify() -> bool` that discards `w` is unusable here. `fips204` is a
//! dev-dependency instead, signing fresh keypairs so this verifier is checked
//! against an implementation that is not itself.
//!
//! # What it does not do
//!
//! There is no signing and no key derivation. Every input is public: a public
//! key, a public signature, and a transaction hash. Nothing here is
//! secret-dependent, so nothing here needs to be constant-time.
//!
//! Every function is named after its counterpart in `py/gen_vectors.py` in the
//! ml-dsa-cairo repository, the reference the Cairo verifier was written
//! against, so the two can be diffed by eye.

mod encode;
mod hints;
mod key;
mod ntt;
mod pack;
mod verify;

use krusty_kms_common::{KmsError, Result};
use starknet_types_core::felt::Felt;

use hints::hint_rows;
use key::{key_material, packed_key_felts};
use pack::{pack_bytes, pack_coeffs, pack_fields};
use verify::verify_internal;

use crate::poseidon_hash_many;

/// The ML-DSA modulus, 2^23 - 2^13 + 1.
const Q: u32 = 8_380_417;
/// Coefficients in one polynomial.
const N_COEFFS: usize = 256;
/// Rows of the public matrix A, and of t1.
const K_ROWS: usize = 6;
/// Columns of A, and the number of z polynomials.
const L_COLS: usize = 5;
/// Dropped low-order bits of t.
const D_BITS: u32 = 13;
/// Nonzero coefficients in the challenge polynomial.
const TAU: usize = 49;
/// Coefficient range of z before the challenge is subtracted.
const GAMMA1: u32 = 1 << 19;
/// The twenty-bit wire field z is packed into, GAMMA1 * 2.
const GAMMA1_FIELD: u32 = 1 << 20;
/// Low-order rounding range, (Q - 1) / 32.
const GAMMA2: u32 = (Q - 1) / 32;
/// Rejection bound on z: GAMMA1 - TAU * eta.
const Z_BOUND: u32 = GAMMA1 - 196;
/// Bytes of c_tilde at this parameter set, lambda / 4.
const CT_BYTES: usize = 48;
/// Maximum total hint positions across all rows.
const OMEGA: usize = 55;
/// Bytes of one packed z polynomial.
const Z_BYTES: usize = 640;
/// Bytes of one packed t1 row.
const T1_ROW_BYTES: usize = 320;
/// Bytes of the key digest `tr`.
const TR_BYTES: usize = 64;
/// Bytes of one packed w1 row.
const W1_ROW_BYTES: usize = 128;
/// Bytes of the hint bitfield: OMEGA positions then one count per row.
const HINT_BYTES: usize = 61;
/// Twenty-bit z fields on the wire: 256 per polynomial plus four of padding.
const Z_WIRE_FIELDS: usize = 5 * N_COEFFS + 4;
/// Offsets that make the M' and K' rows non-negative before packing.
const OFFSET_M: i128 = 1 << 36;
const OFFSET_K: i128 = 1 << 58;

/// Bytes in an ML-DSA-65 public key.
pub const ML_DSA_PUBLIC_KEY_BYTES: usize = 1952;
/// Bytes in an ML-DSA-65 signature.
pub const ML_DSA_SIGNATURE_BYTES: usize = 3309;
/// Felts the packed verification key occupies: 768 A, 154 T, 3 tr.
pub const ML_DSA_KEY_FELTS: usize = 925;
/// Felts one transaction's signature occupies, including the packed key.
pub const ML_DSA_PAYLOAD_FELTS: usize = 1830;

fn invalid_key() -> KmsError {
    KmsError::InvalidPublicKey("expected 1952 bytes of ML-DSA-65 public key".into())
}

fn checked_key(public_key: &[u8]) -> Result<&[u8]> {
    if public_key.len() == ML_DSA_PUBLIC_KEY_BYTES {
        Ok(public_key)
    } else {
        Err(invalid_key())
    }
}

// The fixed 32-byte encoding, never a minimal spelling: a shorter message is a
// different message to the verifier. Taking a `Felt` rather than bytes is what
// makes that impossible to get wrong at a call site.
fn message_bytes(transaction_hash: &Felt) -> [u8; 32] {
    transaction_hash.to_bytes_be()
}

/// The 925-felt packed verification key: the argument the account contract
/// re-hashes on chain, and the prefix every transaction signature carries.
pub fn ml_dsa_packed_key(public_key: &[u8]) -> Result<Vec<Felt>> {
    let material = key_material(checked_key(public_key)?).ok_or_else(invalid_key)?;
    let felts = packed_key_felts(&material);
    if felts.len() != ML_DSA_KEY_FELTS {
        return Err(KmsError::CryptoError(
            "ML-DSA packed key has the wrong length".into(),
        ));
    }
    Ok(felts)
}

/// The Poseidon commitment to the packed key — `key_hash`, the account
/// contract's entire constructor and therefore half of its address preimage.
pub fn ml_dsa_key_commitment(public_key: &[u8]) -> Result<Felt> {
    Ok(poseidon_hash_many(&ml_dsa_packed_key(public_key)?))
}

/// Verifies an ML-DSA-65 signature over `transaction_hash` under `public_key`.
///
/// Malformed lengths and any internal rejection return `false` rather than an
/// error, so a caller gating a broadcast gets one decision it can trust.
pub fn ml_dsa_verify(public_key: &[u8], transaction_hash: &Felt, signature: &[u8]) -> bool {
    if public_key.len() != ML_DSA_PUBLIC_KEY_BYTES || signature.len() != ML_DSA_SIGNATURE_BYTES {
        return false;
    }
    verify_internal(public_key, &message_bytes(transaction_hash), signature).ok
}

/// The full 1,830-felt transaction signature: the packed key, then the
/// felt-native signature and its verification hints.
///
/// Errors rather than returning a payload whose identity could not be proven,
/// because the contract's rejection of a wrong one carries no diagnosis.
pub fn ml_dsa_signature_payload(
    public_key: &[u8],
    transaction_hash: &Felt,
    signature: &[u8],
) -> Result<Vec<Felt>> {
    let key = checked_key(public_key)?;
    if signature.len() != ML_DSA_SIGNATURE_BYTES {
        return Err(KmsError::CryptoError(
            "expected 3309 bytes of ML-DSA-65 signature".into(),
        ));
    }
    let transcript = verify_internal(key, &message_bytes(transaction_hash), signature);
    if !transcript.ok {
        return Err(KmsError::CryptoError(
            "ML-DSA-65 signature does not verify under this key".into(),
        ));
    }
    let material = key_material(key).ok_or_else(invalid_key)?;
    let rows = hint_rows(&material, signature, &transcript.w_rows)?;

    let w_flat: Vec<u128> = transcript
        .w_rows
        .iter()
        .flat_map(|row| row.iter().map(|c| u128::from(*c)))
        .collect();

    let mut payload = packed_key_felts(&material);
    payload.extend(signature_felts(signature)?);
    payload.extend(pack_coeffs(&w_flat));
    payload.extend(pack_fields(&rows.m, 37, 3));
    payload.extend(pack_fields(&rows.k, 59, 2));
    if payload.len() != ML_DSA_PAYLOAD_FELTS {
        return Err(KmsError::CryptoError(
            "ML-DSA payload has the wrong length".into(),
        ));
    }
    Ok(payload)
}

/// A well-formed ML-DSA signature that verifies against nothing, for fee
/// estimation.
///
/// The account contract runs its full verifier under a query version and then
/// tolerates the failing verdict, so an estimate taken this way includes the
/// real cost of validation without asking the phone for anything. What
/// "well-formed" has to mean is set by the three places the contract's verifier
/// gives up before doing that work, and each field below clears one of them: the
/// hint bytes decode as six empty rows, every z field is GAMMA1 so the centred
/// coefficients are zero and inside the rejection bound, and the w coefficients
/// are zero and so below Q. A malformed dummy is *also* tolerated but exits
/// early, which yields a uselessly low estimate rather than an error.
///
/// The packed key is the real one even though the contract tolerates a wrong
/// one: it costs an expansion the caller already knows how to do, it keeps the
/// measured path identical to a real transaction's, and it means this still
/// works against a class built before that tolerance existed.
pub fn ml_dsa_estimation_signature(public_key: &[u8]) -> Result<Vec<Felt>> {
    let mut payload = ml_dsa_packed_key(public_key)?;
    payload.extend(pack_bytes(&[0u8; CT_BYTES]));
    payload.extend(pack_fields(&vec![u128::from(GAMMA1); Z_WIRE_FIELDS], 20, 6));
    payload.extend(pack_bytes(&[0u8; HINT_BYTES]));
    payload.extend(pack_coeffs(&vec![0u128; K_ROWS * N_COEFFS]));
    payload.extend(pack_fields(
        &vec![OFFSET_M as u128; K_ROWS * N_COEFFS],
        37,
        3,
    ));
    payload.extend(pack_fields(
        &vec![OFFSET_K as u128; K_ROWS * N_COEFFS],
        59,
        2,
    ));
    if payload.len() != ML_DSA_PAYLOAD_FELTS {
        return Err(KmsError::CryptoError(
            "ML-DSA estimation signature has the wrong length".into(),
        ));
    }
    Ok(payload)
}

// c_tilde as packed bytes, z as its raw twenty-bit wire fields padded to a whole
// felt with GAMMA1, then the hint bytes. 111 felts.
fn signature_felts(signature: &[u8]) -> Result<Vec<Felt>> {
    let invalid = || KmsError::CryptoError("ML-DSA signature is malformed".into());
    let mut z_raw = Vec::with_capacity(Z_WIRE_FIELDS);
    for j in 0..L_COLS {
        let start = CT_BYTES + Z_BYTES * j;
        let bytes = signature.get(start..start + Z_BYTES).ok_or_else(invalid)?;
        for g in 0..128 {
            let mut value = 0u64;
            for index in (0..5).rev() {
                value = value * 256 + u64::from(*bytes.get(5 * g + index).ok_or_else(invalid)?);
            }
            z_raw.push(u128::from(value % u64::from(GAMMA1_FIELD)));
            z_raw.push(u128::from(value / u64::from(GAMMA1_FIELD)));
        }
    }
    z_raw.resize(Z_WIRE_FIELDS, u128::from(GAMMA1));

    let mut felts = pack_bytes(signature.get(..CT_BYTES).ok_or_else(invalid)?);
    felts.extend(pack_fields(&z_raw, 20, 6));
    felts.extend(pack_bytes(
        signature
            .get(CT_BYTES + Z_BYTES * L_COLS..)
            .ok_or_else(invalid)?,
    ));
    Ok(felts)
}
