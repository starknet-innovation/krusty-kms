//! Cairo type serialization for TONGO contract interactions.
//!
//! This module handles conversion between Rust types and Cairo felt arrays
//! for contract calldata and response parsing.

use crate::{
    AuditProof, ElGamalCiphertext, ElGamalProof, KmsError, Poe2Proof, PoeProof, ProofOfBit,
    ProofOfTransfer, Range, Result,
};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Serialize a ProjectivePoint to Cairo StarkPoint format `(x, y)`.
///
/// # Errors
/// Returns `KmsError::CryptoError` when the point is at infinity.
pub fn serialize_projective_point(point: &ProjectivePoint) -> Result<(Felt, Felt)> {
    let affine = point
        .to_affine()
        .map_err(|_| KmsError::CryptoError("Invalid point".to_string()))?;

    Ok((affine.x(), affine.y()))
}

/// Deserialize Cairo StarkPoint `(x, y)` to ProjectivePoint.
///
/// # Errors
/// Returns `KmsError::CryptoError` if the coordinates are not on the curve.
pub fn deserialize_projective_point(x: Felt, y: Felt) -> Result<ProjectivePoint> {
    ProjectivePoint::from_affine(x, y)
        .map_err(|_| KmsError::CryptoError("Invalid point coordinates".to_string()))
}

/// Serialize Proof of Exponentiation (PoE) proof for Cairo.
///
/// Cairo serialization: `[Ax, Ay, s]`.
pub fn serialize_poe_proof(proof: &PoeProof) -> Result<Vec<Felt>> {
    Ok(vec![proof.a.x, proof.a.y, proof.s])
}

/// Serialize Proof of Exponentiation 2 (PoE2) proof for Cairo.
///
/// Cairo serialization: `[Ax, Ay, s1, s2]`.
pub fn serialize_poe2_proof(proof: &Poe2Proof) -> Result<Vec<Felt>> {
    Ok(vec![proof.a.x, proof.a.y, proof.s1, proof.s2])
}

/// Serialize ElGamal proof for Cairo.
///
/// Cairo serialization: `[ALx, ALy, ARx, ARy, sb, sr]`.
pub fn serialize_elgamal_proof(proof: &ElGamalProof) -> Result<Vec<Felt>> {
    Ok(vec![
        proof.al.x, proof.al.y, proof.ar.x, proof.ar.y, proof.sb, proof.sr,
    ])
}

/// Convert u128 to Cairo u256 `(low, high)` representation.
#[must_use]
pub fn u128_to_u256(value: u128) -> (Felt, Felt) {
    (Felt::from(value), Felt::ZERO)
}

/// Convert u256 `(low, high)` to u128 if it fits.
///
/// # Errors
/// Returns `KmsError::CryptoError` if the value does not fit into `u128`.
pub fn u256_to_u128(low: Felt, high: Felt) -> Result<u128> {
    if high != Felt::ZERO {
        return Err(KmsError::CryptoError(
            "Value too large for u128".to_string(),
        ));
    }

    let bytes = low.to_bytes_be();
    let mut u128_bytes = [0u8; 16];
    u128_bytes.copy_from_slice(&bytes[16..32]);

    Ok(u128::from_be_bytes(u128_bytes))
}

/// Serialize AEBalance (Authenticated Encryption balance hint).
///
/// # Errors
/// Returns `KmsError::CryptoError` if the ciphertext or nonce lengths are invalid.
pub fn serialize_ae_balance(ciphertext_bytes: &[u8], nonce_bytes: &[u8]) -> Result<Vec<Felt>> {
    if ciphertext_bytes.len() != 64 {
        return Err(KmsError::CryptoError(format!(
            "Ciphertext must be 64 bytes, got {}",
            ciphertext_bytes.len()
        )));
    }
    if nonce_bytes.len() != 24 {
        return Err(KmsError::CryptoError(format!(
            "Nonce must be 24 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let ct_felts = bytes_to_u512(ciphertext_bytes);

    let mut nonce_padded = [0u8; 32];
    nonce_padded[..24].copy_from_slice(nonce_bytes);
    let nonce_felts = bytes_to_u256(&nonce_padded);

    Ok(vec![
        ct_felts.0,
        ct_felts.1,
        ct_felts.2,
        ct_felts.3,
        nonce_felts.0,
        nonce_felts.1,
    ])
}

fn bytes_to_u512(bytes: &[u8]) -> (Felt, Felt, Felt, Felt) {
    let mut limb0 = [0u8; 16];
    let mut limb1 = [0u8; 16];
    let mut limb2 = [0u8; 16];
    let mut limb3 = [0u8; 16];

    limb0.copy_from_slice(&bytes[0..16]);
    limb1.copy_from_slice(&bytes[16..32]);
    limb2.copy_from_slice(&bytes[32..48]);
    limb3.copy_from_slice(&bytes[48..64]);

    (
        Felt::from(u128::from_be_bytes(limb0)),
        Felt::from(u128::from_be_bytes(limb1)),
        Felt::from(u128::from_be_bytes(limb2)),
        Felt::from(u128::from_be_bytes(limb3)),
    )
}

fn bytes_to_u256(bytes: &[u8]) -> (Felt, Felt) {
    let mut low_bytes = [0u8; 16];
    let mut high_bytes = [0u8; 16];

    low_bytes.copy_from_slice(&bytes[16..32]);
    high_bytes.copy_from_slice(&bytes[0..16]);

    (
        Felt::from(u128::from_be_bytes(low_bytes)),
        Felt::from(u128::from_be_bytes(high_bytes)),
    )
}

/// Serialize CairoOption::Some variant.
#[must_use]
pub fn serialize_cairo_some<F>(data: F) -> Vec<Felt>
where
    F: FnOnce() -> Vec<Felt>,
{
    let mut result = vec![Felt::ZERO];
    result.extend(data());
    result
}

/// Serialize CairoOption::None variant.
#[must_use]
pub fn serialize_cairo_none() -> Vec<Felt> {
    vec![Felt::ONE]
}

/// Serialize Audit proof for Cairo.
pub fn serialize_audit_proof(proof: &AuditProof) -> Result<Vec<Felt>> {
    Ok(vec![
        proof.ax.x,
        proof.ax.y,
        proof.al0.x,
        proof.al0.y,
        proof.al1.x,
        proof.al1.y,
        proof.ar1.x,
        proof.ar1.y,
        proof.sx,
        proof.sb,
        proof.sr,
    ])
}

/// Serialize CipherBalance (ElGamal ciphertext) for Cairo.
pub fn serialize_cipher_balance(cipher: &ElGamalCiphertext) -> Result<Vec<Felt>> {
    let (l_x, l_y) = serialize_projective_point(&cipher.l)?;
    let (r_x, r_y) = serialize_projective_point(&cipher.r)?;

    Ok(vec![l_x, l_y, r_x, r_y])
}

/// Serialize ProofOfBit for Cairo.
pub fn serialize_bit_proof(proof: &ProofOfBit) -> Result<Vec<Felt>> {
    Ok(vec![
        proof.a0.x, proof.a0.y, proof.a1.x, proof.a1.y, proof.c0, proof.s0, proof.s1,
    ])
}

/// Serialize Range proof for Cairo.
pub fn serialize_range(range: &Range) -> Result<Vec<Felt>> {
    let mut felts = Vec::new();

    felts.push(Felt::from(range.commitments.len()));
    for commitment in &range.commitments {
        felts.push(commitment.x);
        felts.push(commitment.y);
    }

    felts.push(Felt::from(range.proofs.len()));
    for proof in &range.proofs {
        felts.extend(serialize_bit_proof(proof)?);
    }

    Ok(felts)
}

/// Serialize ProofOfTransfer for Cairo.
pub fn serialize_proof_of_transfer(proof: &ProofOfTransfer) -> Result<Vec<Felt>> {
    let mut felts = Vec::new();

    for point in [
        &proof.a_x,
        &proof.a_r,
        &proof.a_r2,
        &proof.a_b,
        &proof.a_b2,
        &proof.a_v,
        &proof.a_v2,
        &proof.a_bar,
    ] {
        felts.push(point.x);
        felts.push(point.y);
    }

    felts.extend([proof.s_x, proof.s_r, proof.s_b, proof.s_b2, proof.s_r2]);
    felts.extend(serialize_range(&proof.range)?);
    felts.extend(serialize_range(&proof.range2)?);

    Ok(felts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SerializablePoint;

    #[test]
    fn serialize_poe_proof_keeps_typed_felts() {
        let proof = PoeProof {
            a: SerializablePoint {
                x: Felt::from(1u64),
                y: Felt::from(2u64),
            },
            s: Felt::from(3u64),
            c: Felt::from(4u64),
        };

        assert_eq!(
            serialize_poe_proof(&proof).unwrap(),
            vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)]
        );
    }

    #[test]
    fn serialize_ae_balance_validates_sizes() {
        assert!(serialize_ae_balance(&[0u8; 63], &[0u8; 24]).is_err());
        assert!(serialize_ae_balance(&[0u8; 64], &[0u8; 23]).is_err());
    }

    #[test]
    fn serialize_roundtrip_point() {
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let point = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let (x, y) = serialize_projective_point(&point).unwrap();
        let recovered = deserialize_projective_point(x, y).unwrap();

        assert_eq!(serialize_projective_point(&recovered).unwrap(), (g_x, g_y));
    }

    #[test]
    fn serialize_range_emits_lengths() {
        let range = Range {
            commitments: vec![SerializablePoint {
                x: Felt::from(1u64),
                y: Felt::from(2u64),
            }],
            proofs: vec![ProofOfBit {
                a0: SerializablePoint {
                    x: Felt::from(3u64),
                    y: Felt::from(4u64),
                },
                a1: SerializablePoint {
                    x: Felt::from(5u64),
                    y: Felt::from(6u64),
                },
                c0: Felt::from(7u64),
                s0: Felt::from(8u64),
                s1: Felt::from(9u64),
            }],
        };

        let felts = serialize_range(&range).unwrap();
        assert_eq!(felts[0], Felt::ONE);
        assert_eq!(felts[3], Felt::ONE);
    }
}
