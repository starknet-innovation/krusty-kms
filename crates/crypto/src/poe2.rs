//! Two-variable Proof of Exponentiation (PoE2) protocol.
//!
//! Implements Okamoto's protocol for proving knowledge of x1 and x2 such that
//! y = g1^x1 * g2^x2 without revealing x1 or x2.
//!
//! This uses two cryptographically independent generator points (G and H).

use crate::curve::StarkCurve;
use crate::hash::compute_challenge_single;
use crate::scalar;
use krusty_kms_common::{Poe2Proof, Result, SecretFelt, SerializablePoint};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Two-variable Proof of Exponentiation protocol.
pub struct ProofOfExponentiation2;

impl ProofOfExponentiation2 {
    /// Generate a proof that y = g1^x1 * g2^x2 using Okamoto's protocol.
    ///
    /// # Arguments
    /// * `x1` - First secret exponent
    /// * `x2` - Second secret exponent
    /// * `g1` - First generator point
    /// * `g2` - Second generator point
    /// * `prefix` - Fiat-Shamir prefix
    ///
    /// # Protocol
    /// ```text
    /// P: k1,k2 <-- R          sends    A = g1^k1 * g2^k2
    /// V: c <-- R              sends    c
    /// P: s1 = k1 + c*x1
    /// P: s2 = k2 + c*x2       sends    s1, s2
    /// ```
    ///
    /// Verifier checks: g1^s1 * g2^s2 == A + y^c
    ///
    /// # Returns
    /// A tuple of (y, proof) where y = g1^x1 * g2^x2
    ///
    /// # Cyclomatic Complexity: 1
    pub fn prove(
        x1: &Felt,
        x2: &Felt,
        g1: &ProjectivePoint,
        g2: &ProjectivePoint,
        prefix: &Felt,
    ) -> Result<(ProjectivePoint, Poe2Proof)> {
        // Compute y = g1^x1 * g2^x2
        let g1_x1 = StarkCurve::mul(x1, Some(g1));
        let g2_x2 = StarkCurve::mul(x2, Some(g2));
        let y = StarkCurve::add(&g1_x1, &g2_x2);

        // Generate random k1, k2 (wrapped in SecretFelt for zeroization on drop)
        let k1 = SecretFelt::new(Self::random_felt());
        let k2 = SecretFelt::new(Self::random_felt());

        // Compute commitment A = g1^k1 * g2^k2
        let g1_k1 = StarkCurve::mul(k1.expose_secret(), Some(g1));
        let g2_k2 = StarkCurve::mul(k2.expose_secret(), Some(g2));
        let a = StarkCurve::add(&g1_k1, &g2_k2);

        // Compute Fiat-Shamir challenge c = H(prefix, A)
        let c = compute_challenge_single(prefix, &a)?;

        // Compute responses s1 = k1 + c*x1, s2 = k2 + c*x2 (mod curve order)
        let c_x1 = scalar::scalar_mul(&c, x1)?;
        let s1 = scalar::scalar_add(k1.expose_secret(), &c_x1)?;

        let c_x2 = scalar::scalar_mul(&c, x2)?;
        let s2 = scalar::scalar_add(k2.expose_secret(), &c_x2)?;

        let proof = Poe2Proof {
            a: SerializablePoint::try_from_projective(&a)?,
            s1: format!("{:#x}", s1),
            s2: format!("{:#x}", s2),
            c: format!("{:#x}", c),
        };

        Ok((y, proof))
    }

    /// Verify a PoE2 proof that y = g1^x1 * g2^x2.
    ///
    /// # Arguments
    /// * `y` - The claimed result (y = g1^x1 * g2^x2)
    /// * `g1` - First generator point
    /// * `g2` - Second generator point
    /// * `proof` - The proof to verify
    /// * `prefix` - Fiat-Shamir prefix used during proof generation
    ///
    /// # Verification Equation
    /// Checks that: g1^s1 * g2^s2 == A + y^c
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    ///
    /// # Cyclomatic Complexity: 2
    pub fn verify(
        y: &ProjectivePoint,
        g1: &ProjectivePoint,
        g2: &ProjectivePoint,
        proof: &Poe2Proof,
        prefix: &Felt,
    ) -> Result<bool> {
        // Parse proof components
        let a = proof.a.to_affine()?;
        let a_proj = StarkCurve::affine_to_projective(&a);
        let s1 = Felt::from_hex(&proof.s1)
            .map_err(|e| krusty_kms_common::KmsError::DeserializationError(e.to_string()))?;
        let s2 = Felt::from_hex(&proof.s2)
            .map_err(|e| krusty_kms_common::KmsError::DeserializationError(e.to_string()))?;
        let c = Felt::from_hex(&proof.c)
            .map_err(|e| krusty_kms_common::KmsError::DeserializationError(e.to_string()))?;

        // Recompute challenge
        let c_computed = compute_challenge_single(prefix, &a_proj)?;
        if c != c_computed {
            return Ok(false);
        }

        // Verify equation: g1^s1 * g2^s2 == A + y^c
        // LHS = g1^s1 * g2^s2
        let g1_s1 = StarkCurve::mul(&s1, Some(g1));
        let g2_s2 = StarkCurve::mul(&s2, Some(g2));
        let lhs = StarkCurve::add(&g1_s1, &g2_s2);

        // RHS = A + y^c
        let y_c = StarkCurve::mul(&c, Some(y));
        let rhs = StarkCurve::add(&a_proj, &y_c);

        let lhs_affine = StarkCurve::projective_to_affine(&lhs)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs)?;

        Ok(lhs_affine == rhs_affine)
    }

    /// Internal verification with explicit parameters (used by withdraw proofs).
    ///
    /// Verifies g1^s1 * g2^s2 = A + y^c without challenge recomputation.
    ///
    /// # Cyclomatic Complexity: 1
    pub fn verify_internal(
        y: &ProjectivePoint,
        g1: &ProjectivePoint,
        g2: &ProjectivePoint,
        a: &ProjectivePoint,
        c: &Felt,
        s1: &Felt,
        s2: &Felt,
    ) -> Result<bool> {
        // Verify equation: g1^s1 * g2^s2 == A + y^c
        // LHS = g1^s1 * g2^s2
        let g1_s1 = StarkCurve::mul(s1, Some(g1));
        let g2_s2 = StarkCurve::mul(s2, Some(g2));
        let lhs = StarkCurve::add(&g1_s1, &g2_s2);

        // RHS = A + y^c
        let y_c = StarkCurve::mul(c, Some(y));
        let rhs = StarkCurve::add(a, &y_c);

        let lhs_affine = StarkCurve::projective_to_affine(&lhs)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs)?;

        Ok(lhs_affine == rhs_affine)
    }

    fn random_felt() -> Felt {
        crate::random::random_felt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poe2_prove_and_verify() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        let valid = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_poe2_invalid_proof() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, mut proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();

        // Tamper with the proof
        proof.s1 = format!("{:#x}", Felt::from(1u64));

        let valid = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_poe2_against_test_vector() {
        // Test vector: poe2_small with x1=100, x2=200
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, _proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        let y_affine = StarkCurve::projective_to_affine(&y).unwrap();

        // Expected from test vector
        let expected_x = Felt::from_dec_str(
            "297633267828633508661315091011792547838924890808287136208503741002601293838",
        )
        .unwrap();
        let expected_y_coord = Felt::from_dec_str(
            "1902201579949854795993467498432482593523374905282349902200318352114598489869",
        )
        .unwrap();

        println!("PoE2 y:    x={}, y={}", y_affine.x(), y_affine.y());
        println!("Expected:  x={}, y={}", expected_x, expected_y_coord);

        assert_eq!(y_affine.x(), expected_x, "x mismatch");
        assert_eq!(y_affine.y(), expected_y_coord, "y mismatch");
    }

    #[test]
    fn test_poe2_commutativity() {
        // Verify that the protocol produces correct y regardless of order
        let x1 = Felt::from(50u64);
        let x2 = Felt::from(75u64);
        let prefix = Felt::from(42u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        // Compute y = g1^x1 * g2^x2
        let (y1, proof1) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();

        // Verify the proof
        let valid1 = ProofOfExponentiation2::verify(&y1, &g1, &g2, &proof1, &prefix).unwrap();
        assert!(valid1);

        // Also verify that different x values produce different y values
        let x3 = Felt::from(51u64);
        let (y2, _) = ProofOfExponentiation2::prove(&x3, &x2, &g1, &g2, &prefix).unwrap();

        let y1_affine = StarkCurve::projective_to_affine(&y1).unwrap();
        let y2_affine = StarkCurve::projective_to_affine(&y2).unwrap();

        assert_ne!(
            y1_affine, y2_affine,
            "Different x1 should produce different y"
        );
    }

    #[test]
    fn test_poe2_zero_exponents() {
        let x1 = Felt::ZERO;
        let x2 = Felt::ZERO;
        let prefix = Felt::from(42u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        let valid = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix).unwrap();

        assert!(valid);
        // y = g1^0 * g2^0 = identity * identity = identity
        assert!(StarkCurve::is_infinity(&y));
    }

    #[test]
    fn test_poe2_verify_invalid_hex_s1() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, mut proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        proof.s1 = "invalid_hex".to_string();

        let result = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix);
        assert!(result.is_err());
    }

    #[test]
    fn test_poe2_verify_invalid_hex_s2() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, mut proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        proof.s2 = "invalid_hex".to_string();

        let result = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix);
        assert!(result.is_err());
    }

    #[test]
    fn test_poe2_verify_invalid_challenge() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, mut proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        proof.c = format!("{:#x}", Felt::from(999999u64));

        let valid = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_poe2_verify_wrong_prefix() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);
        let prefix = Felt::from(999u64);
        let wrong_prefix = Felt::from(1000u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let (y, proof) = ProofOfExponentiation2::prove(&x1, &x2, &g1, &g2, &prefix).unwrap();
        let valid = ProofOfExponentiation2::verify(&y, &g1, &g2, &proof, &wrong_prefix).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_poe2_verify_internal() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        // Compute y = g1^x1 * g2^x2
        let g1_x1 = StarkCurve::mul(&x1, Some(&g1));
        let g2_x2 = StarkCurve::mul(&x2, Some(&g2));
        let y = StarkCurve::add(&g1_x1, &g2_x2);

        // Generate commitment and response manually
        let k1 = Felt::from(12345u64);
        let k2 = Felt::from(67890u64);
        let g1_k1 = StarkCurve::mul(&k1, Some(&g1));
        let g2_k2 = StarkCurve::mul(&k2, Some(&g2));
        let a = StarkCurve::add(&g1_k1, &g2_k2);

        let c = Felt::from(11111u64);

        // s1 = k1 + c*x1, s2 = k2 + c*x2
        let c_x1 = scalar::scalar_mul(&c, &x1).unwrap();
        let s1 = scalar::scalar_add(&k1, &c_x1).unwrap();
        let c_x2 = scalar::scalar_mul(&c, &x2).unwrap();
        let s2 = scalar::scalar_add(&k2, &c_x2).unwrap();

        let valid =
            ProofOfExponentiation2::verify_internal(&y, &g1, &g2, &a, &c, &s1, &s2).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_poe2_verify_internal_wrong_response() {
        let x1 = Felt::from(100u64);
        let x2 = Felt::from(200u64);

        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();

        let g1_x1 = StarkCurve::mul(&x1, Some(&g1));
        let g2_x2 = StarkCurve::mul(&x2, Some(&g2));
        let y = StarkCurve::add(&g1_x1, &g2_x2);

        let k1 = Felt::from(12345u64);
        let k2 = Felt::from(67890u64);
        let g1_k1 = StarkCurve::mul(&k1, Some(&g1));
        let g2_k2 = StarkCurve::mul(&k2, Some(&g2));
        let a = StarkCurve::add(&g1_k1, &g2_k2);

        let c = Felt::from(11111u64);

        // Use wrong s1 value
        let wrong_s1 = Felt::from(1u64);
        let c_x2 = scalar::scalar_mul(&c, &x2).unwrap();
        let s2 = scalar::scalar_add(&k2, &c_x2).unwrap();

        let valid =
            ProofOfExponentiation2::verify_internal(&y, &g1, &g2, &a, &c, &wrong_s1, &s2).unwrap();
        assert!(!valid);
    }
}
