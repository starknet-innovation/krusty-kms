//! Fiat-Shamir challenge generation using Pedersen hash.
//! Also includes Poseidon hash support for prefix computation.

use krusty_kms_common::Result;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, Poseidon, StarkHash};

/// Generate a Fiat-Shamir challenge using Pedersen hash.
///
/// This function implements the deterministic challenge generation for
/// zero-knowledge proofs using the Fiat-Shamir heuristic.
///
/// # Cyclomatic Complexity: 1 (single loop, no branches)
pub fn compute_challenge(prefix: &Felt, points: &[&ProjectivePoint]) -> Result<Felt> {
    let mut current = *prefix;

    for point in points {
        let affine = point
            .to_affine()
            .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;

        current = Pedersen::hash(&current, &affine.x());
        current = Pedersen::hash(&current, &affine.y());
    }

    Ok(current)
}

/// Compute challenge for a single point (common case optimization).
#[inline]
pub fn compute_challenge_single(prefix: &Felt, point: &ProjectivePoint) -> Result<Felt> {
    compute_challenge(prefix, &[point])
}

/// Compute challenge for two points (common case optimization).
#[inline]
pub fn compute_challenge_pair(
    prefix: &Felt,
    point1: &ProjectivePoint,
    point2: &ProjectivePoint,
) -> Result<Felt> {
    compute_challenge(prefix, &[point1, point2])
}

/// Compute challenge for three points (common case optimization).
#[inline]
pub fn compute_challenge_triple(
    prefix: &Felt,
    point1: &ProjectivePoint,
    point2: &ProjectivePoint,
    point3: &ProjectivePoint,
) -> Result<Felt> {
    compute_challenge(prefix, &[point1, point2, point3])
}

/// Hash multiple field elements together using Pedersen.
pub fn hash_felts(felts: &[Felt]) -> Felt {
    felts
        .iter()
        .fold(Felt::ZERO, |acc, felt| Pedersen::hash(&acc, felt))
}

/// Hash multiple field elements using Poseidon hash.
/// This is equivalent to TypeScript's poseidonHashMany.
pub fn poseidon_hash_many(felts: &[Felt]) -> Felt {
    Poseidon::hash_array(felts)
}

/// Compute challenge using Poseidon hash with prefix and commitment points.
/// This matches Cairo's challenge computation: poseidon_hash + reduce_modulo_order.
pub fn compute_poseidon_challenge(prefix: &Felt, points: &[&ProjectivePoint]) -> Result<Felt> {
    let mut felts = vec![*prefix];

    for point in points {
        let affine = point
            .to_affine()
            .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;
        felts.push(affine.x());
        felts.push(affine.y());
    }

    let hash = Poseidon::hash_array(&felts);

    // CRITICAL: Reduce modulo curve order, matching Cairo's reduce_modulo_order
    // This is required for the challenge to be a valid scalar in curve operations
    crate::scalar::reduce_scalar(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StarkCurve;

    #[test]
    fn test_challenge_deterministic() {
        let prefix = Felt::from(42u64);
        let point = StarkCurve::generator();

        let challenge1 = compute_challenge_single(&prefix, &point).unwrap();
        let challenge2 = compute_challenge_single(&prefix, &point).unwrap();

        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_challenge_different_prefix() {
        let prefix1 = Felt::from(42u64);
        let prefix2 = Felt::from(43u64);
        let point = StarkCurve::generator();

        let challenge1 = compute_challenge_single(&prefix1, &point).unwrap();
        let challenge2 = compute_challenge_single(&prefix2, &point).unwrap();

        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_hash_felts() {
        let felts = vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)];
        let hash1 = hash_felts(&felts);
        let hash2 = hash_felts(&felts);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_challenge_pair() {
        let prefix = Felt::from(42u64);
        let point1 = StarkCurve::generator();
        let point2 = StarkCurve::mul(&Felt::from(2u64), Some(&point1));

        let challenge = compute_challenge_pair(&prefix, &point1, &point2).unwrap();
        assert_ne!(challenge, Felt::ZERO);
    }

    #[test]
    fn test_challenge_triple() {
        let prefix = Felt::from(42u64);
        let point1 = StarkCurve::generator();
        let point2 = StarkCurve::mul(&Felt::from(2u64), Some(&point1));
        let point3 = StarkCurve::mul(&Felt::from(3u64), Some(&point1));

        let challenge = compute_challenge_triple(&prefix, &point1, &point2, &point3).unwrap();
        assert_ne!(challenge, Felt::ZERO);
    }

    #[test]
    fn test_poseidon_hash_many() {
        let felts = vec![Felt::from(1u64), Felt::from(2u64), Felt::from(3u64)];
        let hash = poseidon_hash_many(&felts);
        assert_ne!(hash, Felt::ZERO);
    }

    #[test]
    fn test_compute_poseidon_challenge() {
        let prefix = Felt::from(42u64);
        let point = StarkCurve::generator();

        let challenge = compute_poseidon_challenge(&prefix, &[&point]).unwrap();
        assert_ne!(challenge, Felt::ZERO);
    }

    #[test]
    fn test_compute_challenge_multiple_points() {
        let prefix = Felt::from(42u64);
        let g = StarkCurve::generator();
        let p2 = StarkCurve::mul(&Felt::from(5u64), Some(&g));
        let p3 = StarkCurve::mul(&Felt::from(10u64), Some(&g));

        let challenge = compute_challenge(&prefix, &[&g, &p2, &p3]).unwrap();
        assert_ne!(challenge, Felt::ZERO);
    }
}
