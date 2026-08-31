//! The packed verification key: the argument the account contract re-hashes on
//! chain, and the prefix every transaction signature carries.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use starknet_types_core::felt::Felt;

use super::encode::unpack_t1;
use super::ntt::{expand_a, intt, Poly};
use super::pack::{pack_bytes, pack_coeffs};
use super::{D_BITS, K_ROWS, T1_ROW_BYTES, TR_BYTES};

/// A public key expanded into the form the verifier needs.
///
/// `A = InvNTT(ExpandA(rho))`, `T = t1 * 2^d`, `tr = H(pk, 64)`. Held together
/// because the payload builder needs all three and re-expanding would be both
/// slow and a chance to disagree with itself.
pub(super) struct KeyMaterial {
    pub(super) a_coefficients: Vec<Vec<Poly>>,
    pub(super) t_rows: Vec<Poly>,
    pub(super) tr: [u8; TR_BYTES],
}

/// Expands a public key, or `None` when it is the wrong shape.
pub(super) fn key_material(public_key: &[u8]) -> Option<KeyMaterial> {
    let a_coefficients = expand_a(public_key.get(..32)?)?
        .iter()
        .map(|row| row.iter().map(intt).collect())
        .collect();

    let mut t_rows = Vec::with_capacity(K_ROWS);
    for i in 0..K_ROWS {
        let start = 32 + T1_ROW_BYTES * i;
        let mut row = unpack_t1(public_key.get(start..start + T1_ROW_BYTES)?)?;
        for coefficient in &mut row {
            *coefficient <<= D_BITS;
        }
        t_rows.push(row);
    }

    Some(KeyMaterial {
        a_coefficients,
        t_rows,
        tr: shake256_64(public_key),
    })
}

/// `H(pk, 64)` — the key digest FIPS 204 binds the message to.
pub(super) fn shake256_64(input: &[u8]) -> [u8; TR_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut out = [0u8; TR_BYTES];
    hasher.finalize_xof().read(&mut out);
    out
}

/// The 925 felts: 768 for A, 154 for T, 3 for tr.
pub(super) fn packed_key_felts(material: &KeyMaterial) -> Vec<Felt> {
    let a_flat: Vec<u128> = material
        .a_coefficients
        .iter()
        .flatten()
        .flat_map(|poly| poly.iter().map(|c| u128::from(*c)))
        .collect();
    let t_flat: Vec<u128> = material
        .t_rows
        .iter()
        .flat_map(|row| row.iter().map(|c| u128::from(*c)))
        .collect();

    let mut felts = pack_coeffs(&a_flat);
    felts.extend(pack_coeffs(&t_flat));
    felts.extend(pack_bytes(&material.tr));
    felts
}
