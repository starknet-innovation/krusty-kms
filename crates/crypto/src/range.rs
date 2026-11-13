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

/// Reject unsupported range widths before allocating randomness or indexing a proof.
pub fn validate_bit_size(bit_size: usize) -> Result<()> {
    if bit_size == 0 {
        return Err(krusty_kms_common::KmsError::CryptoError(
            "bit_size must be at least 1".to_string(),
        ));
    }
    if bit_size > 128 {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "bit_size {bit_size} exceeds maximum 128"
        )));
    }
    Ok(())
}

/// Computes the total randomness from per-bit random values.
///
/// Computes r = sum(random_values\[i\] * 2^i) for i in 0..random_values.len()
///
/// This is useful when you need to know `r` before calling `prove_with_randomness`,
/// e.g. to compute cipher balance coordinates for prefix hashing.
pub fn compute_total_randomness(random_values: &[Felt]) -> Result<Felt> {
    validate_bit_size(random_values.len())?;
    let mut r = Felt::ZERO;
    for (i, r_inn) in random_values.iter().enumerate() {
        let pow = Felt::from(1u128 << i);
        let r_inn_pow = scalar::scalar_mul(&pow, r_inn)?;
        r = scalar::scalar_add(&r, &r_inn_pow)?;
    }
    Ok(r)
}

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
    validate_bit_size(bit_size)?;
    let random_values = random_felts(bit_size);
    prove_with_randomness(b, bit_size, g1, g2, initial_prefix, &random_values)
}

/// Generates a range proof using pre-generated random values.
///
/// Identical to [`prove`] but uses the supplied `random_values` instead of
/// generating fresh ones. This breaks the circular dependency where the prefix
/// needs cipher balance coordinates that depend on `r`, but `r` comes from the
/// range proof which needs the prefix.
///
/// # Arguments
/// * `b` - The value to prove is in range
/// * `bit_size` - Number of bits (range is [0, 2^bit_size - 1])
/// * `g1` - First generator
/// * `g2` - Second generator
/// * `initial_prefix` - Prefix for challenge computation
/// * `random_values` - Pre-generated random felt values (one per bit)
///
/// # Returns
/// Tuple of (range proof, total randomness r where V = g1^b * g2^r)
pub fn prove_with_randomness(
    b: u128,
    bit_size: usize,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    initial_prefix: &Felt,
    random_values: &[Felt],
) -> Result<(Range, Felt)> {
    validate_bit_size(bit_size)?;

    if random_values.len() != bit_size {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "random_values length {} != bit_size {}",
            random_values.len(),
            bit_size
        )));
    }

    let max_value = if bit_size == 128 {
        u128::MAX
    } else {
        (1u128 << bit_size) - 1
    };

    if b > max_value {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "Value {} is not in range [0, {}]",
            b, max_value
        )));
    }

    // Convert to binary (little-endian: bit 0 is LSB)
    let b_bin: Vec<u8> = (0..bit_size).map(|i| ((b >> i) & 1) as u8).collect();

    // OPTIMIZATION: Generate all bit proofs in PARALLEL (8-10x speedup expected on 8-core CPU)
    // This is safe because each bit proof is independent - only the final accumulation
    // must be sequential to maintain determinism.
    #[cfg(feature = "parallel")]
    let bit_results: Result<Vec<(ProjectivePoint, ProofOfBit, Felt)>> = (0..bit_size)
        .into_par_iter()
        .map(|i| {
            let bit = b_bin[i];
            let r_inn = &random_values[i];
            let prefix = *initial_prefix + Felt::from(i as u64);
            let (v, proof) = bit::prove(bit, r_inn, g1, g2, &prefix)?;
            Ok((v, proof, *r_inn))
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let bit_results: Result<Vec<(ProjectivePoint, ProofOfBit, Felt)>> = (0..bit_size)
        .map(|i| {
            let bit = b_bin[i];
            let r_inn = &random_values[i];
            let prefix = *initial_prefix + Felt::from(i as u64);
            let (v, proof) = bit::prove(bit, r_inn, g1, g2, &prefix)?;
            Ok((v, proof, *r_inn))
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
        commitments.push(SerializablePoint::try_from_projective(&v)?);

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
    validate_bit_size(bit_size)?;
    // Check lengths match
    if range.commitments.len() != bit_size || range.proofs.len() != bit_size {
        return Err(krusty_kms_common::KmsError::CryptoError(format!(
            "Length mismatch: commitments={}, proofs={}, bit_size={}",
            range.commitments.len(),
            range.proofs.len(),
            bit_size
        )));
    }

    // Verify first bit and initialize accumulator
    let v0_commitment = range.commitments[0].to_affine()?;
    let v0 = StarkCurve::affine_to_projective(&v0_commitment);

    let prefix0 = *initial_prefix;
    if !bit::verify(&v0, g1, g2, &range.proofs[0], &prefix0)? {
        return Err(krusty_kms_common::KmsError::CryptoError(
            "Bit proof failed at index 0".to_string(),
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
        let prefix = *initial_prefix + Felt::from(i as u64);
        if !bit::verify(&v, g1, g2, &range.proofs[i], &prefix)? {
            return Err(krusty_kms_common::KmsError::CryptoError(format!(
                "Bit proof failed at index {}",
                i
            )));
        }

        // V_total = V_total + V * pow
        let v_pow = StarkCurve::mul(&pow, Some(&v));
        v_total = StarkCurve::add(&v_total, &v_pow);
    }

    Ok(v_total)
}

#[cfg(test)]
mod tests;
