//! Cairo type serialization for TONGO contract interactions.
//!
//! This module handles conversion between Rust types and Cairo felt arrays
//! for contract calldata and response parsing.

use krusty_kms_common::{
    AuditProof, ElGamalCiphertext, ElGamalProof, Poe2Proof, PoeProof, ProofOfBit, ProofOfTransfer,
    Range, Result,
};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Serialize a ProjectivePoint to Cairo StarkPoint format (x, y).
///
/// # Cyclomatic Complexity: 1
pub fn serialize_projective_point(point: &ProjectivePoint) -> Result<(Felt, Felt)> {
    let affine = point
        .to_affine()
        .map_err(|_| krusty_kms_common::KmsError::CryptoError("Invalid point".to_string()))?;

    Ok((affine.x(), affine.y()))
}

/// Deserialize Cairo StarkPoint (x, y) to ProjectivePoint.
///
/// # Cyclomatic Complexity: 1
pub fn deserialize_projective_point(x: Felt, y: Felt) -> Result<ProjectivePoint> {
    ProjectivePoint::from_affine(x, y).map_err(|_| {
        krusty_kms_common::KmsError::CryptoError("Invalid point coordinates".to_string())
    })
}

/// Serialize Proof of Exponentiation (PoE) proof for Cairo.
///
/// Note: The Rust PoeProof structure contains { a: Point, s: String, c: String },
/// but Cairo only needs { A: Point, s: felt252 } because the challenge is recomputed on-chain.
///
/// Cairo serialization: `[Ax, Ay, s]` (3 felts)
///
/// # Cyclomatic Complexity: 2
pub fn serialize_poe_proof(proof: &PoeProof) -> Result<Vec<Felt>> {
    // Convert the SerializablePoint to felts
    let a_x = Felt::from_hex(&proof.a.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid point x: {}", e)))?;
    let a_y = Felt::from_hex(&proof.a.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid point y: {}", e)))?;

    // Convert s string to Felt (s is hex format like "0x123abc")
    let s_felt = Felt::from_hex(&proof.s).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid s scalar: {}", e))
    })?;

    // Serialize as: [Ax, Ay, s]
    Ok(vec![a_x, a_y, s_felt])
}

/// Serialize Proof of Exponentiation 2 (PoE2) proof for Cairo (Okamoto's protocol).
///
/// Note: The Rust Poe2Proof structure contains { a: Point, s1: String, s2: String, c: String },
/// but Cairo only needs { A: Point, s1: felt252, s2: felt252 }.
///
/// Cairo serialization: `[Ax, Ay, s1, s2]` (4 felts)
///
/// # Cyclomatic Complexity: 2
pub fn serialize_poe2_proof(proof: &Poe2Proof) -> Result<Vec<Felt>> {
    // Convert the SerializablePoint to felts
    let a_x = Felt::from_hex(&proof.a.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid point x: {}", e)))?;
    let a_y = Felt::from_hex(&proof.a.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid point y: {}", e)))?;

    // Convert s1 and s2 strings to Felts (hex format)
    let s1_felt = Felt::from_hex(&proof.s1).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid s1 scalar: {}", e))
    })?;
    let s2_felt = Felt::from_hex(&proof.s2).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid s2 scalar: {}", e))
    })?;

    // Serialize as: [Ax, Ay, s1, s2]
    Ok(vec![a_x, a_y, s1_felt, s2_felt])
}

/// Serialize ElGamal proof for Cairo.
///
/// Note: The Rust ElGamalProof structure contains { al: Point, ar: Point, sb: String, sr: String, c: String },
/// but Cairo only needs { AL: Point, AR: Point, sb: felt252, sr: felt252 }.
///
/// Cairo serialization: `[ALx, ALy, ARx, ARy, sb, sr]` (6 felts)
///
/// # Cyclomatic Complexity: 2
pub fn serialize_elgamal_proof(proof: &ElGamalProof) -> Result<Vec<Felt>> {
    // Convert AL point
    let al_x = Felt::from_hex(&proof.al.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL.x: {}", e)))?;
    let al_y = Felt::from_hex(&proof.al.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL.y: {}", e)))?;

    // Convert AR point
    let ar_x = Felt::from_hex(&proof.ar.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AR.x: {}", e)))?;
    let ar_y = Felt::from_hex(&proof.ar.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AR.y: {}", e)))?;

    // Convert sb and sr strings to Felts (hex format)
    let sb_felt = Felt::from_hex(&proof.sb).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid sb scalar: {}", e))
    })?;
    let sr_felt = Felt::from_hex(&proof.sr).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid sr scalar: {}", e))
    })?;

    // Serialize as: [ALx, ALy, ARx, ARy, sb, sr]
    Ok(vec![al_x, al_y, ar_x, ar_y, sb_felt, sr_felt])
}

/// Convert u128 to Cairo u256 (low, high) representation.
///
/// # Cyclomatic Complexity: 1
pub fn u128_to_u256(value: u128) -> (Felt, Felt) {
    // u256 in Cairo is represented as (low: u128, high: u128)
    // For values that fit in u128, high is always 0
    (Felt::from(value), Felt::ZERO)
}

/// Convert u256 (low, high) to u128 if it fits.
///
/// # Cyclomatic Complexity: 2
pub fn u256_to_u128(low: Felt, high: Felt) -> Result<u128> {
    if high != Felt::ZERO {
        return Err(krusty_kms_common::KmsError::CryptoError(
            "Value too large for u128".to_string(),
        ));
    }

    // Convert low felt to u128
    let bytes = low.to_bytes_be();
    let mut u128_bytes = [0u8; 16];
    u128_bytes.copy_from_slice(&bytes[16..32]); // Take lower 16 bytes

    Ok(u128::from_be_bytes(u128_bytes))
}

/// Serialize AEBalance (Authenticated Encryption balance hint).
///
/// Cairo struct:
/// ```cairo
/// struct AEBalance {
///     ciphertext: u512,  // 4 felts (64 bytes)
///     nonce: u256,       // 2 felts (32 bytes, 24-byte nonce padded)
/// }
/// ```
///
/// # Arguments
/// * `ciphertext_bytes` - 64 bytes of XChaCha20-Poly1305 ciphertext
/// * `nonce_bytes` - 24 bytes of XChaCha20 nonce (will be padded to 32)
///
/// # Cyclomatic Complexity: 2
pub fn serialize_ae_balance(ciphertext_bytes: &[u8], nonce_bytes: &[u8]) -> Result<Vec<Felt>> {
    if ciphertext_bytes.len() != 64 {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "Ciphertext must be 64 bytes, got {}",
            ciphertext_bytes.len()
        )));
    }
    if nonce_bytes.len() != 24 {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "Nonce must be 24 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    // Convert 64-byte ciphertext to u512 (4 u128 limbs)
    let ct_felts = bytes_to_u512(ciphertext_bytes);

    // Pad 24-byte nonce to 32 bytes for u256
    let mut nonce_padded = [0u8; 32];
    nonce_padded[..24].copy_from_slice(nonce_bytes);
    let nonce_felts = bytes_to_u256(&nonce_padded);

    // Serialize as: [ct_0, ct_1, ct_2, ct_3, nonce_low, nonce_high]
    Ok(vec![
        ct_felts.0,
        ct_felts.1,
        ct_felts.2,
        ct_felts.3,
        nonce_felts.0,
        nonce_felts.1,
    ])
}

/// Convert 64 bytes to U512 represented as 4 felts (each u128).
///
/// # Cyclomatic Complexity: 1
fn bytes_to_u512(bytes: &[u8]) -> (Felt, Felt, Felt, Felt) {
    // Split into 4 chunks of 16 bytes each (u128 limbs)
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

/// Convert 32 bytes to U256 represented as 2 felts (low, high).
///
/// # Cyclomatic Complexity: 1
fn bytes_to_u256(bytes: &[u8]) -> (Felt, Felt) {
    let mut low_bytes = [0u8; 16];
    let mut high_bytes = [0u8; 16];

    low_bytes.copy_from_slice(&bytes[16..32]); // Lower 16 bytes
    high_bytes.copy_from_slice(&bytes[0..16]); // Upper 16 bytes

    (
        Felt::from(u128::from_be_bytes(low_bytes)),  // low
        Felt::from(u128::from_be_bytes(high_bytes)), // high
    )
}

/// Serialize CairoOption::Some variant.
///
/// Cairo enum: `enum Option<T> { Some(T), None }`
/// Serialization: `[0, ...T]` where 0 is the Some variant tag
///
/// # Cyclomatic Complexity: 1
#[must_use]
pub fn serialize_cairo_some<F>(data: F) -> Vec<Felt>
where
    F: FnOnce() -> Vec<Felt>,
{
    let mut result = vec![Felt::ZERO]; // Variant 0 = Some
    result.extend(data());
    result
}

/// Serialize CairoOption::None variant.
///
/// Cairo enum: `enum Option<T> { Some(T), None }`
/// Serialization: `[1]` where 1 is the None variant tag
///
/// # Cyclomatic Complexity: 1
#[must_use]
pub fn serialize_cairo_none() -> Vec<Felt> {
    vec![Felt::ONE] // Variant 1 = None
}

/// Serialize Audit proof for Cairo.
///
/// The AuditProof structure contains points and scalars proving balance declaration.
/// Cairo only needs the commitment points and response scalars (challenge is recomputed).
///
/// Cairo serialization: `[Ax_x, Ax_y, AL0_x, AL0_y, AL1_x, AL1_y, AR1_x, AR1_y, sx, sb, sr]` (11 felts)
///
/// # Cyclomatic Complexity: 2
pub fn serialize_audit_proof(proof: &AuditProof) -> Result<Vec<Felt>> {
    // Convert Ax point
    let ax_x = Felt::from_hex(&proof.ax.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid Ax.x: {}", e)))?;
    let ax_y = Felt::from_hex(&proof.ax.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid Ax.y: {}", e)))?;

    // Convert AL0 point
    let al0_x = Felt::from_hex(&proof.al0.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL0.x: {}", e)))?;
    let al0_y = Felt::from_hex(&proof.al0.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL0.y: {}", e)))?;

    // Convert AL1 point
    let al1_x = Felt::from_hex(&proof.al1.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL1.x: {}", e)))?;
    let al1_y = Felt::from_hex(&proof.al1.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AL1.y: {}", e)))?;

    // Convert AR1 point
    let ar1_x = Felt::from_hex(&proof.ar1.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AR1.x: {}", e)))?;
    let ar1_y = Felt::from_hex(&proof.ar1.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid AR1.y: {}", e)))?;

    // Convert scalars sx, sb, sr to Felts (hex format)
    let sx_felt = Felt::from_hex(&proof.sx).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid sx scalar: {}", e))
    })?;
    let sb_felt = Felt::from_hex(&proof.sb).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid sb scalar: {}", e))
    })?;
    let sr_felt = Felt::from_hex(&proof.sr).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid sr scalar: {}", e))
    })?;

    // Serialize as: [Ax_x, Ax_y, AL0_x, AL0_y, AL1_x, AL1_y, AR1_x, AR1_y, sx, sb, sr]
    Ok(vec![
        ax_x, ax_y, al0_x, al0_y, al1_x, al1_y, ar1_x, ar1_y, sx_felt, sb_felt, sr_felt,
    ])
}

/// Serialize CipherBalance (ElGamal ciphertext) for Cairo.
///
/// CipherBalance consists of two curve points (L, R).
/// Cairo serialization: `[Lx, Ly, Rx, Ry]` (4 felts)
///
/// # Cyclomatic Complexity: 1
pub fn serialize_cipher_balance(cipher: &ElGamalCiphertext) -> Result<Vec<Felt>> {
    let (l_x, l_y) = serialize_projective_point(&cipher.l)?;
    let (r_x, r_y) = serialize_projective_point(&cipher.r)?;

    Ok(vec![l_x, l_y, r_x, r_y])
}

/// Serialize ProofOfBit for Cairo.
///
/// ProofOfBit proves that a committed value is either 0 or 1 using an OR proof.
///
/// Cairo serialization: `[A0_x, A0_y, A1_x, A1_y, c0, s0, s1]` (7 felts)
/// Note: c0 IS needed because Cairo's bitProof struct includes it
///
/// # Cyclomatic Complexity: 2
pub fn serialize_bit_proof(proof: &ProofOfBit) -> Result<Vec<Felt>> {
    // Convert A0 point
    let a0_x = Felt::from_hex(&proof.a0.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid A0.x: {}", e)))?;
    let a0_y = Felt::from_hex(&proof.a0.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid A0.y: {}", e)))?;

    // Convert A1 point
    let a1_x = Felt::from_hex(&proof.a1.x)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid A1.x: {}", e)))?;
    let a1_y = Felt::from_hex(&proof.a1.y)
        .map_err(|e| krusty_kms_common::KmsError::CryptoError(format!("Invalid A1.y: {}", e)))?;

    // Convert c0, s0, and s1 strings to Felts (hex format)
    let c0_felt = Felt::from_hex(&proof.c0).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid c0 scalar: {}", e))
    })?;
    let s0_felt = Felt::from_hex(&proof.s0).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid s0 scalar: {}", e))
    })?;
    let s1_felt = Felt::from_hex(&proof.s1).map_err(|e| {
        krusty_kms_common::KmsError::CryptoError(format!("Invalid s1 scalar: {}", e))
    })?;

    // Serialize as: [A0_x, A0_y, A1_x, A1_y, c0, s0, s1]
    Ok(vec![a0_x, a0_y, a1_x, a1_y, c0_felt, s0_felt, s1_felt])
}

/// Serialize Range proof for Cairo.
///
/// Range proof proves that a value is in [0, 2^bit_size - 1] using bit decomposition.
/// Contains commitments for each bit and corresponding bit proofs.
///
/// Cairo serialization: `[len, commitment0_x, commitment0_y, ..., proof0_fields..., ...]`
/// Each commitment is 2 felts, each proof is 7 felts (A0_x, A0_y, A1_x, A1_y, c0, s0, s1)
///
/// # Cyclomatic Complexity: 3
pub fn serialize_range(range: &Range) -> Result<Vec<Felt>> {
    let mut felts = Vec::new();

    // Serialize commitments Span: length + data
    felts.push(Felt::from(range.commitments.len()));

    // Serialize all commitments (each is 2 felts)
    for commitment in &range.commitments {
        let x = Felt::from_hex(&commitment.x).map_err(|e| {
            krusty_kms_common::KmsError::CryptoError(format!("Invalid commitment.x: {}", e))
        })?;
        let y = Felt::from_hex(&commitment.y).map_err(|e| {
            krusty_kms_common::KmsError::CryptoError(format!("Invalid commitment.y: {}", e))
        })?;
        felts.push(x);
        felts.push(y);
    }

    // Serialize proofs Span: length + data
    felts.push(Felt::from(range.proofs.len()));

    // Serialize all proofs (each is 7 felts: A0_x, A0_y, A1_x, A1_y, c0, s0, s1)
    for proof in &range.proofs {
        let proof_felts = serialize_bit_proof(proof)?;
        felts.extend(proof_felts);
    }

    Ok(felts)
}

/// Serialize ProofOfTransfer for Cairo.
///
/// ProofOfTransfer contains 8 commitment points, 5 scalar responses, and 2 range proofs.
/// This proves correct transfer amount encryption, valid ranges, and balance equations.
///
/// Cairo serialization:
/// - 8 commitment points (16 felts): A_x, A_r, A_r2, A_b, A_b2, A_v, A_v2, A_bar
/// - 5 scalar responses (5 felts): s_x, s_r, s_b, s_b2, s_r2
/// - range proof (variable felts)
/// - range2 proof (variable felts)
///
/// Note: R_aux/R_aux2 moved to separate auxiliarCipher fields in calldata.
///
/// # Cyclomatic Complexity: 2
pub fn serialize_proof_of_transfer(proof: &ProofOfTransfer) -> Result<Vec<Felt>> {
    let mut felts = Vec::new();

    // Serialize 8 commitment points (2 felts each = 16 total)
    for point_ref in [
        &proof.a_x,
        &proof.a_r,
        &proof.a_r2,
        &proof.a_b,
        &proof.a_b2,
        &proof.a_v,
        &proof.a_v2,
        &proof.a_bar,
    ] {
        let x = Felt::from_hex(&point_ref.x).map_err(|e| {
            krusty_kms_common::KmsError::CryptoError(format!("Invalid point.x: {}", e))
        })?;
        let y = Felt::from_hex(&point_ref.y).map_err(|e| {
            krusty_kms_common::KmsError::CryptoError(format!("Invalid point.y: {}", e))
        })?;
        felts.push(x);
        felts.push(y);
    }

    // Serialize 5 scalar responses (5 felts)
    for scalar_str in [&proof.s_x, &proof.s_r, &proof.s_b, &proof.s_b2, &proof.s_r2] {
        let scalar_felt = Felt::from_hex(scalar_str).map_err(|e| {
            krusty_kms_common::KmsError::CryptoError(format!("Invalid scalar: {}", e))
        })?;
        felts.push(scalar_felt);
    }

    // Serialize range proof (variable felts)
    let range_felts = serialize_range(&proof.range)?;
    felts.extend(range_felts);

    // Serialize range2 proof (variable felts)
    let range2_felts = serialize_range(&proof.range2)?;
    felts.extend(range2_felts);

    Ok(felts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_projective_point() {
        // Create a test point (generator)
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let point = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let (x, y) = serialize_projective_point(&point).unwrap();

        assert_eq!(x, g_x);
        assert_eq!(y, g_y);
    }

    #[test]
    fn test_deserialize_projective_point() {
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();

        let point = deserialize_projective_point(g_x, g_y).unwrap();
        let affine = point.to_affine().unwrap();

        assert_eq!(affine.x(), g_x);
        assert_eq!(affine.y(), g_y);
    }

    #[test]
    fn test_roundtrip_point() {
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();

        let point1 = deserialize_projective_point(g_x, g_y).unwrap();
        let (x, y) = serialize_projective_point(&point1).unwrap();
        let point2 = deserialize_projective_point(x, y).unwrap();

        let affine1 = point1.to_affine().unwrap();
        let affine2 = point2.to_affine().unwrap();

        assert_eq!(affine1.x(), affine2.x());
        assert_eq!(affine1.y(), affine2.y());
    }

    #[test]
    fn test_serialize_poe_proof() {
        use krusty_kms_common::SerializablePoint;

        let proof = PoeProof {
            a: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            s: "0x7b".to_string(), // 123 in hex (matching actual proof format)
            c: "unused".to_string(),
        };

        let serialized = serialize_poe_proof(&proof).unwrap();

        // Should be [Ax, Ay, s] = 3 felts
        assert_eq!(serialized.len(), 3);
        assert_eq!(serialized[0], Felt::from(1u64));
        assert_eq!(serialized[1], Felt::from(2u64));
        assert_eq!(serialized[2], Felt::from(123u64));
    }

    #[test]
    fn test_serialize_poe2_proof() {
        use krusty_kms_common::SerializablePoint;

        let proof = Poe2Proof {
            a: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            s1: "0x7b".to_string(), // 123 in hex (matching actual proof format)
            s2: "0x1c8".to_string(), // 456 in hex (matching actual proof format)
            c: "unused".to_string(),
        };

        let serialized = serialize_poe2_proof(&proof).unwrap();

        // Should be [Ax, Ay, s1, s2] = 4 felts
        assert_eq!(serialized.len(), 4);
        assert_eq!(serialized[0], Felt::from(1u64));
        assert_eq!(serialized[1], Felt::from(2u64));
        assert_eq!(serialized[2], Felt::from(123u64));
        assert_eq!(serialized[3], Felt::from(456u64));
    }

    #[test]
    fn test_serialize_elgamal_proof() {
        use krusty_kms_common::SerializablePoint;

        let proof = ElGamalProof {
            al: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            ar: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            sb: "0x6f".to_string(), // 111 in hex (matching actual proof format)
            sr: "0xde".to_string(), // 222 in hex (matching actual proof format)
            c: "unused".to_string(),
        };

        let serialized = serialize_elgamal_proof(&proof).unwrap();

        // Should be [ALx, ALy, ARx, ARy, sb, sr] = 6 felts
        assert_eq!(serialized.len(), 6);
        assert_eq!(serialized[0], Felt::from(1u64));
        assert_eq!(serialized[1], Felt::from(2u64));
        assert_eq!(serialized[2], Felt::from(3u64));
        assert_eq!(serialized[3], Felt::from(4u64));
        assert_eq!(serialized[4], Felt::from(111u64));
        assert_eq!(serialized[5], Felt::from(222u64));
    }

    #[test]
    fn test_u128_to_u256() {
        let value = 123456789u128;
        let (low, high) = u128_to_u256(value);

        assert_eq!(low, Felt::from(value));
        assert_eq!(high, Felt::ZERO);
    }

    #[test]
    fn test_u256_to_u128() {
        let value = 123456789u128;
        let (low, high) = u128_to_u256(value);
        let result = u256_to_u128(low, high).unwrap();

        assert_eq!(result, value);
    }

    #[test]
    fn test_u256_to_u128_overflow() {
        let result = u256_to_u128(Felt::ZERO, Felt::ONE);
        assert!(result.is_err());
    }

    #[test]
    fn test_cairo_option_some() {
        let data = serialize_cairo_some(|| vec![Felt::from(42u64), Felt::from(43u64)]);

        assert_eq!(data.len(), 3);
        assert_eq!(data[0], Felt::ZERO); // Some variant
        assert_eq!(data[1], Felt::from(42u64));
        assert_eq!(data[2], Felt::from(43u64));
    }

    #[test]
    fn test_cairo_option_none() {
        let data = serialize_cairo_none();

        assert_eq!(data.len(), 1);
        assert_eq!(data[0], Felt::ONE); // None variant
    }

    #[test]
    fn test_serialize_ae_balance() {
        // Create test ciphertext (64 bytes) and nonce (24 bytes)
        let ciphertext = [0x42u8; 64];
        let nonce = [0x99u8; 24];

        let result = serialize_ae_balance(&ciphertext, &nonce).unwrap();

        // Should be 6 felts: 4 for u512 ciphertext + 2 for u256 nonce
        assert_eq!(result.len(), 6);

        // Verify all felts are non-zero (since we used non-zero bytes)
        for felt in &result {
            assert_ne!(*felt, Felt::ZERO);
        }
    }

    #[test]
    fn test_serialize_ae_balance_invalid_sizes() {
        // Test invalid ciphertext size
        let ciphertext_short = [0u8; 32];
        let nonce = [0u8; 24];
        assert!(serialize_ae_balance(&ciphertext_short, &nonce).is_err());

        // Test invalid nonce size
        let ciphertext = [0u8; 64];
        let nonce_short = [0u8; 16];
        assert!(serialize_ae_balance(&ciphertext, &nonce_short).is_err());
    }

    #[test]
    fn test_bytes_to_u512_roundtrip() {
        let original_bytes = [0x12u8; 64];
        let (f0, f1, f2, f3) = bytes_to_u512(&original_bytes);

        // Each felt should represent a u128 from 16 bytes of 0x12
        let expected_u128 = u128::from_be_bytes([0x12u8; 16]);
        assert_eq!(f0, Felt::from(expected_u128));
        assert_eq!(f1, Felt::from(expected_u128));
        assert_eq!(f2, Felt::from(expected_u128));
        assert_eq!(f3, Felt::from(expected_u128));
    }

    #[test]
    fn test_bytes_to_u256_roundtrip() {
        let bytes = [0xAAu8; 32];
        let (low, high) = bytes_to_u256(&bytes);

        // Both low and high should be the same since all bytes are 0xAA
        let expected_u128 = u128::from_be_bytes([0xAAu8; 16]);
        assert_eq!(low, Felt::from(expected_u128));
        assert_eq!(high, Felt::from(expected_u128));
    }

    #[test]
    fn test_serialize_projective_point_invalid() {
        // Create an identity point (point at infinity)
        let point = ProjectivePoint::identity();
        let result = serialize_projective_point(&point);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_projective_point_invalid() {
        // Use coordinates that aren't on the curve
        let invalid_x = Felt::from(1u64);
        let invalid_y = Felt::from(2u64);
        let result = deserialize_projective_point(invalid_x, invalid_y);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_poe_proof_invalid_hex() {
        use krusty_kms_common::SerializablePoint;

        let proof = PoeProof {
            a: SerializablePoint {
                x: "invalid_hex".to_string(),
                y: "0x2".to_string(),
            },
            s: "0x7b".to_string(),
            c: "unused".to_string(),
        };

        let result = serialize_poe_proof(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_poe2_proof_invalid_s1() {
        use krusty_kms_common::SerializablePoint;

        let proof = Poe2Proof {
            a: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            s1: "invalid_hex".to_string(),
            s2: "0x1c8".to_string(),
            c: "unused".to_string(),
        };

        let result = serialize_poe2_proof(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_elgamal_proof_invalid_sb() {
        use krusty_kms_common::SerializablePoint;

        let proof = ElGamalProof {
            al: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            ar: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            sb: "invalid_hex".to_string(),
            sr: "0xde".to_string(),
            c: "unused".to_string(),
        };

        let result = serialize_elgamal_proof(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_audit_proof() {
        use krusty_kms_common::SerializablePoint;

        let proof = AuditProof {
            ax: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            al0: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            al1: SerializablePoint {
                x: "0x5".to_string(),
                y: "0x6".to_string(),
            },
            ar1: SerializablePoint {
                x: "0x7".to_string(),
                y: "0x8".to_string(),
            },
            sx: "0x9".to_string(),
            sb: "0xa".to_string(),
            sr: "0xb".to_string(),
            c: "unused".to_string(),
        };

        let serialized = serialize_audit_proof(&proof).unwrap();

        // Should be 11 felts: 4 points * 2 + 3 scalars
        assert_eq!(serialized.len(), 11);
        assert_eq!(serialized[0], Felt::from(1u64)); // ax.x
        assert_eq!(serialized[1], Felt::from(2u64)); // ax.y
        assert_eq!(serialized[8], Felt::from(9u64)); // sx
        assert_eq!(serialized[9], Felt::from(10u64)); // sb
        assert_eq!(serialized[10], Felt::from(11u64)); // sr
    }

    #[test]
    fn test_serialize_audit_proof_invalid_hex() {
        use krusty_kms_common::SerializablePoint;

        let proof = AuditProof {
            ax: SerializablePoint {
                x: "invalid".to_string(),
                y: "0x2".to_string(),
            },
            al0: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            al1: SerializablePoint {
                x: "0x5".to_string(),
                y: "0x6".to_string(),
            },
            ar1: SerializablePoint {
                x: "0x7".to_string(),
                y: "0x8".to_string(),
            },
            sx: "0x9".to_string(),
            sb: "0xa".to_string(),
            sr: "0xb".to_string(),
            c: "unused".to_string(),
        };

        let result = serialize_audit_proof(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_cipher_balance() {
        // Use generator point for valid test
        let g_x =
            Felt::from_hex("0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca")
                .unwrap();
        let g_y =
            Felt::from_hex("0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f")
                .unwrap();
        let point = ProjectivePoint::from_affine(g_x, g_y).unwrap();

        let cipher = ElGamalCiphertext {
            l: point.clone(),
            r: point,
        };

        let serialized = serialize_cipher_balance(&cipher).unwrap();

        // Should be 4 felts: Lx, Ly, Rx, Ry
        assert_eq!(serialized.len(), 4);
        assert_eq!(serialized[0], g_x);
        assert_eq!(serialized[1], g_y);
        assert_eq!(serialized[2], g_x);
        assert_eq!(serialized[3], g_y);
    }

    #[test]
    fn test_serialize_cipher_balance_invalid() {
        let cipher = ElGamalCiphertext {
            l: ProjectivePoint::identity(),
            r: ProjectivePoint::identity(),
        };

        let result = serialize_cipher_balance(&cipher);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_bit_proof() {
        use krusty_kms_common::SerializablePoint;

        let proof = ProofOfBit {
            a0: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            a1: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            c0: "0x5".to_string(),
            s0: "0x6".to_string(),
            s1: "0x7".to_string(),
        };

        let serialized = serialize_bit_proof(&proof).unwrap();

        // Should be 7 felts: 2 points * 2 + 3 scalars
        assert_eq!(serialized.len(), 7);
        assert_eq!(serialized[0], Felt::from(1u64));
        assert_eq!(serialized[6], Felt::from(7u64));
    }

    #[test]
    fn test_serialize_bit_proof_invalid_hex() {
        use krusty_kms_common::SerializablePoint;

        let proof = ProofOfBit {
            a0: SerializablePoint {
                x: "0x1".to_string(),
                y: "0x2".to_string(),
            },
            a1: SerializablePoint {
                x: "0x3".to_string(),
                y: "0x4".to_string(),
            },
            c0: "invalid".to_string(),
            s0: "0x6".to_string(),
            s1: "0x7".to_string(),
        };

        let result = serialize_bit_proof(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_range() {
        use krusty_kms_common::SerializablePoint;

        let range = Range {
            commitments: vec![
                SerializablePoint {
                    x: "0x1".to_string(),
                    y: "0x2".to_string(),
                },
                SerializablePoint {
                    x: "0x3".to_string(),
                    y: "0x4".to_string(),
                },
            ],
            proofs: vec![
                ProofOfBit {
                    a0: SerializablePoint {
                        x: "0xa".to_string(),
                        y: "0xb".to_string(),
                    },
                    a1: SerializablePoint {
                        x: "0xc".to_string(),
                        y: "0xd".to_string(),
                    },
                    c0: "0xe".to_string(),
                    s0: "0xf".to_string(),
                    s1: "0x10".to_string(),
                },
                ProofOfBit {
                    a0: SerializablePoint {
                        x: "0x11".to_string(),
                        y: "0x12".to_string(),
                    },
                    a1: SerializablePoint {
                        x: "0x13".to_string(),
                        y: "0x14".to_string(),
                    },
                    c0: "0x15".to_string(),
                    s0: "0x16".to_string(),
                    s1: "0x17".to_string(),
                },
            ],
        };

        let serialized = serialize_range(&range).unwrap();

        // 1 (commitments len) + 4 (2 commitments * 2) + 1 (proofs len) + 14 (2 proofs * 7) = 20
        assert_eq!(serialized.len(), 20);
        assert_eq!(serialized[0], Felt::from(2u64)); // commitments length
        assert_eq!(serialized[5], Felt::from(2u64)); // proofs length
    }

    #[test]
    fn test_serialize_range_invalid_commitment() {
        use krusty_kms_common::SerializablePoint;

        let range = Range {
            commitments: vec![SerializablePoint {
                x: "invalid".to_string(),
                y: "0x2".to_string(),
            }],
            proofs: vec![],
        };

        let result = serialize_range(&range);
        assert!(result.is_err());
    }

    #[test]
    fn test_u128_to_u256_zero() {
        let (low, high) = u128_to_u256(0);
        assert_eq!(low, Felt::ZERO);
        assert_eq!(high, Felt::ZERO);
    }

    #[test]
    fn test_u128_to_u256_max() {
        let (low, high) = u128_to_u256(u128::MAX);
        assert_eq!(low, Felt::from(u128::MAX));
        assert_eq!(high, Felt::ZERO);
    }

    #[test]
    fn test_u256_to_u128_zero() {
        let result = u256_to_u128(Felt::ZERO, Felt::ZERO).unwrap();
        assert_eq!(result, 0);
    }
}
