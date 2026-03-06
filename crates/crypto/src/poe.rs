//! Proof of Exponentiation (PoE) protocol.
//!
//! Implements the Chaum-Pedersen protocol for proving knowledge of x such that y = g^x
//! without revealing x.

use crate::curve::StarkCurve;
use crate::hash::compute_poseidon_challenge;
use crate::scalar;
use krusty_kms_common::{PoeProof, Result, SecretFelt, SerializablePoint};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Proof of Exponentiation protocol.
pub struct ProofOfExponentiation;

impl ProofOfExponentiation {
    /// Generate a proof that y = g^x.
    ///
    /// # Arguments
    /// * `x` - The secret exponent
    /// * `prefix` - Fiat-Shamir prefix for challenge generation
    ///
    /// # Returns
    /// A tuple of (y, proof) where y = g^x
    ///
    /// # Cyclomatic Complexity: 1 (no branches)
    pub fn prove(x: &Felt, prefix: &Felt) -> Result<(ProjectivePoint, PoeProof)> {
        let g = StarkCurve::generator();

        // Compute y = g^x
        let y = StarkCurve::mul(x, Some(&g));

        // Generate random r (wrapped in SecretFelt for zeroization on drop)
        let r = SecretFelt::new(Self::random_felt());

        // Compute commitment A = g^r
        let a = StarkCurve::mul(r.expose_secret(), Some(&g));

        // Compute Fiat-Shamir challenge c = Poseidon(prefix, A)
        let c = compute_poseidon_challenge(prefix, &[&a])?;

        // Compute response s = r + c*x (mod curve order)
        let c_x = scalar::scalar_mul(&c, x)?;
        let s = scalar::scalar_add(r.expose_secret(), &c_x)?;

        let proof = PoeProof {
            a: SerializablePoint::try_from_projective(&a)?,
            s: format!("{:#x}", s),
            c: format!("{:#x}", c),
        };

        Ok((y, proof))
    }

    /// Verify a PoE proof.
    ///
    /// # Arguments
    /// * `y` - The claimed result (y = g^x)
    /// * `proof` - The proof to verify
    /// * `prefix` - Fiat-Shamir prefix used during proof generation
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    ///
    /// # Cyclomatic Complexity: 2 (one early return)
    pub fn verify(y: &ProjectivePoint, proof: &PoeProof, prefix: &Felt) -> Result<bool> {
        let g = StarkCurve::generator();

        // Parse proof components
        let a = proof.a.to_affine()?;
        let a_proj = StarkCurve::affine_to_projective(&a);
        let s = Felt::from_hex(&proof.s)
            .map_err(|e| krusty_kms_common::KmsError::DeserializationError(e.to_string()))?;
        let c = Felt::from_hex(&proof.c)
            .map_err(|e| krusty_kms_common::KmsError::DeserializationError(e.to_string()))?;

        // Recompute challenge using Poseidon
        let c_computed = compute_poseidon_challenge(prefix, &[&a_proj])?;
        if c != c_computed {
            return Ok(false);
        }

        // Verify equation: g^s = A * y^c
        let lhs = StarkCurve::mul(&s, Some(&g));
        let y_c = StarkCurve::mul(&c, Some(y));
        let rhs = StarkCurve::add(&a_proj, &y_c);

        let lhs_affine = StarkCurve::projective_to_affine(&lhs)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs)?;

        Ok(lhs_affine == rhs_affine)
    }

    /// Internal verification with explicit parameters (used by bit proofs).
    ///
    /// Verifies gen^s = A + y^c without challenge recomputation.
    pub fn verify_internal(
        y: &ProjectivePoint,
        gen: &ProjectivePoint,
        a: &ProjectivePoint,
        c: &Felt,
        s: &Felt,
    ) -> Result<bool> {
        // Verify equation: gen^s = A + y^c
        let lhs = StarkCurve::mul(s, Some(gen));
        let y_c = StarkCurve::mul(c, Some(y));
        let rhs = StarkCurve::add(a, &y_c);

        let lhs_affine = StarkCurve::projective_to_affine(&lhs)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs)?;

        Ok(lhs_affine == rhs_affine)
    }

    /// Generate a random field element.
    fn random_felt() -> Felt {
        crate::random::random_felt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poe_prove_and_verify() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);

        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();
        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_poe_invalid_proof() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);

        let (y, mut proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();

        // Tamper with the proof
        proof.s = format!("{:#x}", Felt::from(999u64));

        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_poe_wrong_prefix() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);
        let wrong_prefix = Felt::from(43u64);

        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();
        let valid = ProofOfExponentiation::verify(&y, &proof, &wrong_prefix).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_poe_zero_exponent() {
        let x = Felt::ZERO;
        let prefix = Felt::from(42u64);

        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();
        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();

        assert!(valid);
        // y = g^0 should be point at infinity
        assert!(StarkCurve::is_infinity(&y));
    }

    #[test]
    fn test_poe_verify_invalid_hex() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);

        let (y, mut proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();

        // Use invalid hex in s
        proof.s = "invalid_hex".to_string();

        let result = ProofOfExponentiation::verify(&y, &proof, &prefix);
        assert!(result.is_err());
    }

    #[test]
    fn test_poe_verify_invalid_challenge_hex() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);

        let (y, mut proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();

        // Use invalid hex in c
        proof.c = "invalid_hex".to_string();

        let result = ProofOfExponentiation::verify(&y, &proof, &prefix);
        assert!(result.is_err());
    }

    #[test]
    fn test_poe_verify_tampered_challenge() {
        let x = Felt::from(100u64);
        let prefix = Felt::from(42u64);

        let (y, mut proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();

        // Tamper with the challenge
        proof.c = format!("{:#x}", Felt::from(999999u64));

        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_poe_verify_internal() {
        let x = Felt::from(100u64);
        let g = StarkCurve::generator();
        let y = StarkCurve::mul(&x, Some(&g));

        // Generate commitment and response manually
        let r = Felt::from(12345u64);
        let a = StarkCurve::mul(&r, Some(&g));
        let c = Felt::from(67890u64);

        // s = r + c*x
        let c_x = scalar::scalar_mul(&c, &x).unwrap();
        let s = scalar::scalar_add(&r, &c_x).unwrap();

        let valid = ProofOfExponentiation::verify_internal(&y, &g, &a, &c, &s).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_poe_verify_internal_wrong_response() {
        let x = Felt::from(100u64);
        let g = StarkCurve::generator();
        let y = StarkCurve::mul(&x, Some(&g));

        let r = Felt::from(12345u64);
        let a = StarkCurve::mul(&r, Some(&g));
        let c = Felt::from(67890u64);

        // Use wrong s value
        let wrong_s = Felt::from(1u64);

        let valid = ProofOfExponentiation::verify_internal(&y, &g, &a, &c, &wrong_s).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_poe_large_exponent() {
        // Test with a large exponent
        let x = Felt::from_hex("0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let prefix = Felt::from(42u64);

        let (y, proof) = ProofOfExponentiation::prove(&x, &prefix).unwrap();
        let valid = ProofOfExponentiation::verify(&y, &proof, &prefix).unwrap();

        assert!(valid);
    }
}
