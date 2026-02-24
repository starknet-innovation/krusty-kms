//! Range proof protocol.
//!
//! Proves that a value b is in the range [0, 2^bit_size - 1] by:
//! 1. Decomposing b into binary: b = sum(b_i * 2^i)
//! 2. Creating commitments V_i = g1^b_i * g2^r_i for each bit
//! 3. Proving each b_i ∈ {0,1} using bit proofs
//! 4. Verifying V = sum(V_i * 2^i) where V = g1^b * g2^r

use crate::bit;
use crate::curve::StarkCurve;
use crate::random::random_felts;
use crate::scalar;
use krusty_kms_common::{ProofOfBit, Range, Result, SerializablePoint};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Generates a range proof that b is in [0, 2^bit_size - 1].
///
/// # Arguments
/// * `b` - The value to prove is in range
/// * `bit_size` - Number of bits (range is [0, 2^bit_size - 1])
/// * `g1` - First generator
/// * `g2` - Second generator
/// * `initial_prefix` - Prefix for challenge computation
///
/// # Returns
/// Tuple of (range proof, total randomness r where V = g1^b * g2^r)
///
/// # Matching TypeScript
/// This directly implements typescript-reference/she/src/protocols/range.ts:prove()
pub fn prove(
    b: u128,
    bit_size: usize,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    initial_prefix: &Felt,
) -> Result<(Range, Felt)> {
    // Check range
    if bit_size > 128 {
        return Err(krusty_kms_common::KmsError::CryptoError(
            format!("bit_size {} exceeds maximum 128", bit_size)
        ));
    }

    let max_value = if bit_size == 128 {
        u128::MAX
    } else {
        (1u128 << bit_size) - 1
    };

    if b > max_value {
        return Err(krusty_kms_common::KmsError::CryptoError(
            format!("Value {} is not in range [0, {}]", b, max_value)
        ));
    }

    // Convert to binary (little-endian: bit 0 is LSB)
    let b_bin: Vec<u8> = (0..bit_size)
        .map(|i| ((b >> i) & 1) as u8)
        .collect();

    // OPTIMIZATION: Generate all random values at once to amortize RNG overhead
    let random_values = random_felts(bit_size);

    // OPTIMIZATION: Generate all bit proofs in PARALLEL (8-10x speedup expected on 8-core CPU)
    // This is safe because each bit proof is independent - only the final accumulation
    // must be sequential to maintain determinism.
    #[cfg(feature = "parallel")]
    let bit_results: Result<Vec<(ProjectivePoint, ProofOfBit, Felt)>> = (0..bit_size)
        .into_par_iter()
        .map(|i| {
            let bit = b_bin[i];
            let r_inn = &random_values[i];
            let prefix = scalar::scalar_add(initial_prefix, &Felt::from(i as u64))?;
            let (v, proof) = bit::prove(bit, r_inn, g1, g2, &prefix)?;
            Ok((v, proof, r_inn.clone()))
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let bit_results: Result<Vec<(ProjectivePoint, ProofOfBit, Felt)>> = (0..bit_size)
        .map(|i| {
            let bit = b_bin[i];
            let r_inn = &random_values[i];
            let prefix = scalar::scalar_add(initial_prefix, &Felt::from(i as u64))?;
            let (v, proof) = bit::prove(bit, r_inn, g1, g2, &prefix)?;
            Ok((v, proof, r_inn.clone()))
        })
        .collect();
    let bit_results = bit_results?;

    // Sequential accumulation phase - must be sequential to maintain determinism
    let mut proofs = Vec::with_capacity(bit_size);
    let mut commitments = Vec::with_capacity(bit_size);
    let mut r = Felt::ZERO;

    for (i, (v, proof, r_inn)) in bit_results.into_iter().enumerate() {
        let pow = Felt::from(1u128 << i);

        proofs.push(proof);
        commitments.push(SerializablePoint::from_projective(&v));

        // r = (r + r_inn * pow) % CURVE_ORDER
        let r_inn_pow = scalar::scalar_mul(&pow, &r_inn)?;
        r = scalar::scalar_add(&r, &r_inn_pow)?;
    }

    let range = Range {
        commitments,
        proofs,
    };

    Ok((range, r))
}

/// Verifies a range proof.
///
/// # Arguments
/// * `range` - The range proof to verify
/// * `bit_size` - Expected bit size
/// * `g1` - First generator
/// * `g2` - Second generator
/// * `initial_prefix` - Prefix for challenge computation
///
/// # Returns
/// The reconstructed V = g1^b * g2^r on success, or error
///
/// # Matching TypeScript
/// This directly implements typescript-reference/she/src/protocols/range.ts:verify()
pub fn verify(
    range: &Range,
    bit_size: usize,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    initial_prefix: &Felt,
) -> Result<ProjectivePoint> {
    // Check lengths match
    if range.commitments.len() != bit_size || range.proofs.len() != bit_size {
        return Err(krusty_kms_common::KmsError::CryptoError(
            format!("Length mismatch: commitments={}, proofs={}, bit_size={}",
                range.commitments.len(), range.proofs.len(), bit_size)
        ));
    }

    // Verify first bit and initialize accumulator
    let v0_commitment = range.commitments[0].to_affine()?;
    let v0 = StarkCurve::affine_to_projective(&v0_commitment);

    let prefix0 = scalar::scalar_add(initial_prefix, &Felt::ZERO)?;
    if !bit::verify(&v0, g1, g2, &range.proofs[0], &prefix0)? {
        return Err(krusty_kms_common::KmsError::CryptoError(
            "Bit proof failed at index 0".to_string()
        ));
    }

    // v_total starts with first bit commitment (multiplied by 2^0 = 1)
    let mut v_total = v0;

    // Process remaining bits
    for i in 1..bit_size {
        let pow = Felt::from(1u128 << i);
        let v_commitment = range.commitments[i].to_affine()?;
        let v = StarkCurve::affine_to_projective(&v_commitment);

        // Verify this bit proof
        let prefix = scalar::scalar_add(initial_prefix, &Felt::from(i as u64))?;
        if !bit::verify(&v, g1, g2, &range.proofs[i], &prefix)? {
            return Err(krusty_kms_common::KmsError::CryptoError(
                format!("Bit proof failed at index {}", i)
            ));
        }

        // V_total = V_total + V * pow
        let v_pow = StarkCurve::mul(&pow, Some(&v));
        v_total = StarkCurve::add(&v_total, &v_pow);
    }

    Ok(v_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_small() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 7u128;
        let bit_size = 8;

        let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
        let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

        // Check V = g1^b * g2^r
        let expected = StarkCurve::add(
            &StarkCurve::mul(&Felt::from(b), Some(&g1)),
            &StarkCurve::mul(&r, Some(&g2))
        );

        let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
        let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

        assert_eq!(v_affine, expected_affine);
    }

    #[test]
    fn test_range_proof_zero() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 0u128;
        let bit_size = 8;

        let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
        let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

        // Check V = g1^0 * g2^r = g2^r
        let expected = StarkCurve::mul(&r, Some(&g2));

        let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
        let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

        assert_eq!(v_affine, expected_affine);
    }

    #[test]
    fn test_range_proof_max_value() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        // Maximum value for 8 bits: 255
        let b = 255u128;
        let bit_size = 8;

        let (range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
        let result = verify(&range, bit_size, &g1, &g2, &prefix);
        assert!(result.is_ok());
    }

    #[test]
    fn test_range_proof_out_of_range() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        // Value 256 is out of range for 8 bits (max is 255)
        let b = 256u128;
        let bit_size = 8;

        let result = prove(b, bit_size, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("not in range"));
        }
    }

    #[test]
    fn test_range_proof_bit_size_too_large() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 1u128;
        let bit_size = 129; // exceeds 128

        let result = prove(b, bit_size, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("exceeds maximum 128"));
        }
    }

    #[test]
    fn test_range_verify_length_mismatch() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 7u128;
        let bit_size = 8;

        let (range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

        // Verify with wrong bit_size
        let result = verify(&range, 16, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("Length mismatch"));
        }
    }

    #[test]
    fn test_range_verify_tampered_commitment() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 7u128;
        let bit_size = 8;

        let (mut range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

        // Tamper with first commitment
        range.commitments[0] = SerializablePoint::try_from_projective(&StarkCurve::generator()).unwrap();

        let result = verify(&range, bit_size, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("Bit proof failed at index 0"));
        }
    }

    #[test]
    fn test_range_verify_tampered_middle_commitment() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        let b = 7u128;
        let bit_size = 8;

        let (mut range, _r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();

        // Tamper with a middle commitment (index 3)
        range.commitments[3] = SerializablePoint::try_from_projective(&StarkCurve::generator()).unwrap();

        let result = verify(&range, bit_size, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("Bit proof failed at index 3"));
        }
    }

    #[test]
    fn test_range_proof_larger_value() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let prefix = Felt::from(42u64);

        // Test with a larger value
        let b = 12345u128;
        let bit_size = 16;

        let (range, r) = prove(b, bit_size, &g1, &g2, &prefix).unwrap();
        let v = verify(&range, bit_size, &g1, &g2, &prefix).unwrap();

        // Check V = g1^b * g2^r
        let expected = StarkCurve::add(
            &StarkCurve::mul(&Felt::from(b), Some(&g1)),
            &StarkCurve::mul(&r, Some(&g2))
        );

        let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
        let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();

        assert_eq!(v_affine, expected_affine);
    }
}
