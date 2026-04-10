//! Bit proof protocol (OR proof for bit ∈ {0,1}).
//!
//! Proves that a commitment V = g1^b * g2^r encodes either b=0 or b=1,
//! without revealing which one. Uses an OR composition of two POE proofs.

use crate::curve::StarkCurve;
use crate::hash::compute_poseidon_challenge;
use crate::poe::ProofOfExponentiation;
use crate::random::random_felt;
use crate::scalar;
use krusty_kms_common::{ProofOfBit, Result, SecretFelt, SerializablePoint};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Simulates a POE proof transcript without knowing the discrete log.
///
/// Generates random (s, c) and computes A = gen^s - y^c, which will verify
/// correctly for the equation gen^s = A + y^c.
///
/// This is used in OR proofs to simulate the branch we're NOT proving.
///
/// # Errors
/// Returns an error if point conversion fails (e.g., point at infinity).
fn simulate_poe(
    y: &ProjectivePoint,
    gen: &ProjectivePoint,
) -> Result<(ProjectivePoint, Felt, Felt)> {
    let s = random_felt();
    let c = random_felt();

    // A = gen^s - y^c
    let gen_s = StarkCurve::mul(&s, Some(gen));
    let y_c = StarkCurve::mul(&c, Some(y));

    // Subtract by negating y_c
    let y_c_affine = StarkCurve::projective_to_affine(&y_c)?;
    let neg_y_c = StarkCurve::affine_to_projective(
        &starknet_types_core::curve::AffinePoint::new(y_c_affine.x(), -y_c_affine.y()).map_err(
            |e| krusty_kms_common::KmsError::CryptoError(format!("Point negation failed: {:?}", e)),
        )?,
    );

    let a = StarkCurve::add(&gen_s, &neg_y_c);

    Ok((a, c, s))
}

/// Proves bit=0 case: V = g2^r (no g1 component).
///
/// Real proof: POE for V = g2^r
/// Simulated proof: POE for V-g1 = g2^r (impossible, so simulated)
fn prove_bit_0(
    random: &Felt,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    prefix: &Felt,
) -> Result<(ProjectivePoint, ProofOfBit)> {
    // V = g2^random
    let v = StarkCurve::mul(random, Some(g2));

    // V1 = V - g1 (for bit=1 case, which we simulate)
    let g1_affine = StarkCurve::projective_to_affine(g1)?;
    let neg_g1 = StarkCurve::affine_to_projective(
        &starknet_types_core::curve::AffinePoint::new(g1_affine.x(), -g1_affine.y()).map_err(
            |e| krusty_kms_common::KmsError::CryptoError(format!("Point negation failed: {:?}", e)),
        )?,
    );
    let v1 = StarkCurve::add(&v, &neg_g1);

    // Simulate the bit=1 proof (we don't know the discrete log of V1 w.r.t. g2)
    let (a1, c1, s1) = simulate_poe(&v1, g2)?;

    // Real proof for bit=0: POE for V = g2^random
    let k = SecretFelt::new(random_felt());
    let a0 = StarkCurve::mul(k.expose_secret(), Some(g2));

    // Compute challenge from commitments: c = H(prefix, V, A0, A1)
    let c = compute_poseidon_challenge(prefix, &[&v, &a0, &a1])?;

    // c0 = c - c1 (mod curve order)
    let c0 = scalar::scalar_sub(&c, &c1)?;

    // s0 = k + c0 * random
    let s0 = scalar::scalar_add(k.expose_secret(), &scalar::scalar_mul(&c0, random)?)?;

    let proof = ProofOfBit {
        a0: SerializablePoint::try_from_projective(&a0)?,
        a1: SerializablePoint::try_from_projective(&a1)?,
        c0,
        s0,
        s1,
    };

    Ok((v, proof))
}

/// Proves bit=1 case: V = g1 + g2^r.
///
/// Real proof: POE for V-g1 = g2^r
/// Simulated proof: POE for V = g2^r (impossible, so simulated)
fn prove_bit_1(
    random: &Felt,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    prefix: &Felt,
) -> Result<(ProjectivePoint, ProofOfBit)> {
    // V = g1 + g2^random
    let g2_r = StarkCurve::mul(random, Some(g2));
    let v = StarkCurve::add(g1, &g2_r);

    // Simulate the bit=0 proof (we don't know the discrete log of V w.r.t. g2)
    let (a0, c0, s0) = simulate_poe(&v, g2)?;

    // Real proof for bit=1: POE for V-g1 = g2^random
    let k = SecretFelt::new(random_felt());
    let a1 = StarkCurve::mul(k.expose_secret(), Some(g2));

    // Compute challenge from commitments: c = H(prefix, V, A0, A1)
    let c = compute_poseidon_challenge(prefix, &[&v, &a0, &a1])?;

    // c1 = c - c0 (mod curve order)
    let c1 = scalar::scalar_sub(&c, &c0)?;

    // s1 = k + c1 * random
    let s1 = scalar::scalar_add(k.expose_secret(), &scalar::scalar_mul(&c1, random)?)?;

    let proof = ProofOfBit {
        a0: SerializablePoint::try_from_projective(&a0)?,
        a1: SerializablePoint::try_from_projective(&a1)?,
        c0,
        s0,
        s1,
    };

    Ok((v, proof))
}

/// Generates a proof that V = g1^bit * g2^random for bit ∈ {0,1}.
///
/// # Arguments
/// * `bit` - The bit value (0 or 1)
/// * `random` - Random blinding factor
/// * `g1` - First generator (for bit value)
/// * `g2` - Second generator (for randomness)
/// * `prefix` - Fiat-Shamir prefix
///
/// # Returns
/// Tuple of (V commitment point, proof)
pub fn prove(
    bit: u8,
    random: &Felt,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    prefix: &Felt,
) -> Result<(ProjectivePoint, ProofOfBit)> {
    match bit {
        0 => prove_bit_0(random, g1, g2, prefix),
        1 => prove_bit_1(random, g1, g2, prefix),
        _ => Err(krusty_kms_common::KmsError::CryptoError(
            "Bit must be 0 or 1".to_string(),
        )),
    }
}

/// Verifies a bit proof.
///
/// Checks that V encodes either bit=0 or bit=1 by verifying both POE equations.
pub fn verify(
    v: &ProjectivePoint,
    g1: &ProjectivePoint,
    g2: &ProjectivePoint,
    proof: &ProofOfBit,
    prefix: &Felt,
) -> Result<bool> {
    let a0 = proof.a0.to_affine()?;
    let a1 = proof.a1.to_affine()?;
    let a0_proj = StarkCurve::affine_to_projective(&a0);
    let a1_proj = StarkCurve::affine_to_projective(&a1);

    let c0 = proof.c0;
    let s0 = proof.s0;
    let s1 = proof.s1;

    // Recompute challenge: c = H(prefix, V, A0, A1)
    let c = compute_poseidon_challenge(prefix, &[v, &a0_proj, &a1_proj])?;

    // c1 = c - c0 (mod curve order)
    let c1 = scalar::scalar_sub(&c, &c0)?;

    // Verify first POE: g2^s0 = A0 + V^c0
    if !ProofOfExponentiation::verify_internal(v, g2, &a0_proj, &c0, &s0)? {
        return Ok(false);
    }

    // V1 = V - g1
    let g1_affine = StarkCurve::projective_to_affine(g1)?;
    let neg_g1 = StarkCurve::affine_to_projective(
        &starknet_types_core::curve::AffinePoint::new(g1_affine.x(), -g1_affine.y()).map_err(
            |e| krusty_kms_common::KmsError::CryptoError(format!("Point negation failed: {:?}", e)),
        )?,
    );
    let v1 = StarkCurve::add(v, &neg_g1);

    // Verify second POE: g2^s1 = A1 + V1^c1
    if !ProofOfExponentiation::verify_internal(&v1, g2, &a1_proj, &c1, &s1)? {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::StarkCurve;

    #[test]
    fn test_prove_bit_0() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let (v, proof) = prove(0, &random, &g1, &g2, &prefix).unwrap();

        // Verify the proof
        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(valid);

        // V should be g2^random for bit=0
        let expected = StarkCurve::mul(&random, Some(&g2));
        let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
        let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();
        assert_eq!(v_affine, expected_affine);
    }

    #[test]
    fn test_prove_bit_1() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let (v, proof) = prove(1, &random, &g1, &g2, &prefix).unwrap();

        // Verify the proof
        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(valid);

        // V should be g1 + g2^random for bit=1
        let g2_r = StarkCurve::mul(&random, Some(&g2));
        let expected = StarkCurve::add(&g1, &g2_r);
        let v_affine = StarkCurve::projective_to_affine(&v).unwrap();
        let expected_affine = StarkCurve::projective_to_affine(&expected).unwrap();
        assert_eq!(v_affine, expected_affine);
    }

    #[test]
    fn test_prove_invalid_bit() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let result = prove(2, &random, &g1, &g2, &prefix);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("Bit must be 0 or 1"));
        }
    }

    #[test]
    fn test_verify_tampered_c0() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let (v, mut proof) = prove(0, &random, &g1, &g2, &prefix).unwrap();

        // Tamper with c0
        proof.c0 = Felt::from(999999u64);

        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_tampered_s0() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let (v, mut proof) = prove(0, &random, &g1, &g2, &prefix).unwrap();

        // Tamper with s0
        proof.s0 = Felt::from(999999u64);

        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_tampered_s1() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);

        let (v, mut proof) = prove(1, &random, &g1, &g2, &prefix).unwrap();

        // Tamper with s1
        proof.s1 = Felt::from(999999u64);

        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_prefix() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::from(12345u64);
        let prefix = Felt::from(42u64);
        let wrong_prefix = Felt::from(43u64);

        let (v, proof) = prove(0, &random, &g1, &g2, &prefix).unwrap();

        // Verify with wrong prefix
        let valid = verify(&v, &g1, &g2, &proof, &wrong_prefix).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_bit_proof_small_random() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random = Felt::ONE; // Use 1 instead of 0 to avoid identity point
        let prefix = Felt::from(42u64);

        let (v, proof) = prove(0, &random, &g1, &g2, &prefix).unwrap();
        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_bit_proof_large_random() {
        let g1 = StarkCurve::generator();
        let g2 = StarkCurve::generator_h();
        let random =
            Felt::from_hex("0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let prefix = Felt::from(42u64);

        let (v, proof) = prove(1, &random, &g1, &g2, &prefix).unwrap();
        let valid = verify(&v, &g1, &g2, &proof, &prefix).unwrap();
        assert!(valid);
    }
}
