//! Zero-knowledge proof implementations for the mental poker protocol.
//!
//! This module provides:
//! - Schnorr identification (proof of key ownership)
//! - Chaum-Pedersen discrete log equality proofs

use crate::error::{MentalPokerError, Result};
use crate::types::{DLEqualityProof, KeyOwnershipProof, PublicKey, SecretKey, SerializablePoint};
use sha2::{Digest, Sha256};
use krusty_kms_crypto::{scalar, StarkCurve};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Compute a Fiat-Shamir challenge from a byte seed.
fn compute_challenge(data: &[u8]) -> Felt {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Convert first 31 bytes to Felt (to stay within field)
    let mut bytes = [0u8; 32];
    bytes[1..].copy_from_slice(&hash[..31]);
    Felt::from_bytes_be(&bytes)
}

/// Schnorr identification protocol for proving key ownership.
pub struct SchnorrProtocol;

impl SchnorrProtocol {
    /// Prove knowledge of secret key corresponding to public key.
    ///
    /// Proves: I know sk such that pk = g^sk
    pub fn prove(pk: &PublicKey, sk: &SecretKey, context: &[u8]) -> Result<KeyOwnershipProof> {
        let g = StarkCurve::GENERATOR;

        // Generate random nonce
        let r = scalar::random_felt();

        // Compute commitment: a = g^r
        let a = StarkCurve::mul(&r, Some(&g));

        // Compute challenge: c = H(context || g || pk || a)
        let a_affine = StarkCurve::projective_to_affine(&a)?;
        let pk_affine = StarkCurve::projective_to_affine(&pk.point)?;
        let g_affine = StarkCurve::projective_to_affine(&g)?;

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(context);
        challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&pk_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&pk_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a_affine.y().to_bytes_be());

        let c = compute_challenge(&challenge_input);

        // Compute response: s = r + c * sk (mod order)
        let c_sk = scalar::scalar_mul(&c, &sk.scalar)?;
        let s = scalar::scalar_add(&r, &c_sk)?;

        Ok(KeyOwnershipProof {
            commitment: SerializablePoint::from_projective(&a)?,
            response: format!("{:#x}", s),
            challenge: format!("{:#x}", c),
        })
    }

    /// Verify a Schnorr proof of key ownership.
    pub fn verify(pk: &PublicKey, proof: &KeyOwnershipProof, context: &[u8]) -> Result<bool> {
        let g = StarkCurve::GENERATOR;

        // Parse proof components
        let a = proof.commitment.to_projective()?;
        let s = Felt::from_hex(&proof.response)
            .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;
        let c = Felt::from_hex(&proof.challenge)
            .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;

        // Recompute challenge
        let a_affine = StarkCurve::projective_to_affine(&a)?;
        let pk_affine = StarkCurve::projective_to_affine(&pk.point)?;
        let g_affine = StarkCurve::projective_to_affine(&g)?;

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(context);
        challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&pk_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&pk_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a_affine.y().to_bytes_be());

        let c_computed = compute_challenge(&challenge_input);
        if c != c_computed {
            return Ok(false);
        }

        // Verify: g^s = a * pk^c
        let lhs = StarkCurve::mul(&s, Some(&g));
        let pk_c = StarkCurve::mul(&c, Some(&pk.point));
        let rhs = StarkCurve::add(&a, &pk_c);

        let lhs_affine = StarkCurve::projective_to_affine(&lhs)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs)?;

        Ok(lhs_affine == rhs_affine)
    }
}

/// Chaum-Pedersen protocol for proving discrete log equality.
pub struct ChaumPedersenProtocol;

impl ChaumPedersenProtocol {
    /// Prove that log_g(y1) = log_h(y2).
    ///
    /// Given g, h, y1 = g^x, y2 = h^x, prove knowledge of x.
    pub fn prove(
        g: &ProjectivePoint,
        h: &ProjectivePoint,
        y1: &ProjectivePoint,
        y2: &ProjectivePoint,
        x: &Felt,
        context: &[u8],
    ) -> Result<DLEqualityProof> {
        // Generate random nonce
        let r = scalar::random_felt();

        // Compute commitments: a1 = g^r, a2 = h^r
        let a1 = StarkCurve::mul(&r, Some(g));
        let a2 = StarkCurve::mul(&r, Some(h));

        // Compute challenge: c = H(context || g || h || y1 || y2 || a1 || a2)
        let g_affine = StarkCurve::projective_to_affine(g)?;
        let h_affine = StarkCurve::projective_to_affine(h)?;
        let y1_affine = StarkCurve::projective_to_affine(y1)?;
        let y2_affine = StarkCurve::projective_to_affine(y2)?;
        let a1_affine = StarkCurve::projective_to_affine(&a1)?;
        let a2_affine = StarkCurve::projective_to_affine(&a2)?;

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(context);
        challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.y().to_bytes_be());

        let c = compute_challenge(&challenge_input);

        // Compute response: s = r + c * x (mod order)
        let c_x = scalar::scalar_mul(&c, x)?;
        let s = scalar::scalar_add(&r, &c_x)?;

        Ok(DLEqualityProof {
            a1: SerializablePoint::from_projective(&a1)?,
            a2: SerializablePoint::from_projective(&a2)?,
            response: format!("{:#x}", s),
            challenge: format!("{:#x}", c),
        })
    }

    /// Verify a Chaum-Pedersen proof of discrete log equality.
    pub fn verify(
        g: &ProjectivePoint,
        h: &ProjectivePoint,
        y1: &ProjectivePoint,
        y2: &ProjectivePoint,
        proof: &DLEqualityProof,
        context: &[u8],
    ) -> Result<bool> {
        // Parse proof components
        let a1 = proof.a1.to_projective()?;
        let a2 = proof.a2.to_projective()?;
        let s = Felt::from_hex(&proof.response)
            .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;
        let c = Felt::from_hex(&proof.challenge)
            .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;

        // Recompute challenge
        let g_affine = StarkCurve::projective_to_affine(g)?;
        let h_affine = StarkCurve::projective_to_affine(h)?;
        let y1_affine = StarkCurve::projective_to_affine(y1)?;
        let y2_affine = StarkCurve::projective_to_affine(y2)?;
        let a1_affine = StarkCurve::projective_to_affine(&a1)?;
        let a2_affine = StarkCurve::projective_to_affine(&a2)?;

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(context);
        challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.y().to_bytes_be());

        let c_computed = compute_challenge(&challenge_input);
        if c != c_computed {
            return Ok(false);
        }

        // Verify: g^s = a1 * y1^c
        let lhs1 = StarkCurve::mul(&s, Some(g));
        let y1_c = StarkCurve::mul(&c, Some(y1));
        let rhs1 = StarkCurve::add(&a1, &y1_c);

        let lhs1_affine = StarkCurve::projective_to_affine(&lhs1)?;
        let rhs1_affine = StarkCurve::projective_to_affine(&rhs1)?;

        if lhs1_affine != rhs1_affine {
            return Ok(false);
        }

        // Verify: h^s = a2 * y2^c
        let lhs2 = StarkCurve::mul(&s, Some(h));
        let y2_c = StarkCurve::mul(&c, Some(y2));
        let rhs2 = StarkCurve::add(&a2, &y2_c);

        let lhs2_affine = StarkCurve::projective_to_affine(&lhs2)?;
        let rhs2_affine = StarkCurve::projective_to_affine(&rhs2)?;

        Ok(lhs2_affine == rhs2_affine)
    }
}

/// Convenience type alias for Chaum-Pedersen proof statements.
///
/// Tuple format: (g, h, A, B) where the proof shows log_g(A) = log_h(B).
pub type ChaumPedersenStatement = (
    ProjectivePoint,
    ProjectivePoint,
    ProjectivePoint,
    ProjectivePoint,
);

/// Internal type alias for batch verification input.
///
/// Format: (g, h, y1, y2, proof, context)
type BatchVerificationInput = (
    ProjectivePoint,
    ProjectivePoint,
    ProjectivePoint,
    ProjectivePoint,
    DLEqualityProof,
    Vec<u8>,
);

/// Batch verify multiple Chaum-Pedersen proofs.
///
/// This is a convenience function that provides the API requested in the task spec.
/// It wraps `BatchVerifier::verify_chaum_pedersen_batch` with a simpler interface.
///
/// # Arguments
/// * `proofs` - Slice of Chaum-Pedersen proofs to verify
/// * `statements` - Slice of (g, h, A, B) tuples representing the statements
///
/// # Returns
/// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
///
/// # Example
/// ```rust
/// use mental_poker::zkp::{batch_verify_chaum_pedersen, ChaumPedersenProtocol};
/// use krusty_kms_crypto::{scalar, StarkCurve};
///
/// let g = StarkCurve::GENERATOR;
/// let h = StarkCurve::GENERATOR_H;
/// let x = scalar::random_felt();
/// let y1 = StarkCurve::mul(&x, Some(&g));
/// let y2 = StarkCurve::mul(&x, Some(&h));
///
/// let context = b"example";
/// let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
///
/// let proofs = vec![proof];
/// let statements = vec![(g, h, y1, y2)];
/// let valid = batch_verify_chaum_pedersen(&proofs, &statements, context).unwrap();
/// assert!(valid);
/// ```
#[must_use = "verification result must be checked"]
pub fn batch_verify_chaum_pedersen(
    proofs: &[DLEqualityProof],
    statements: &[ChaumPedersenStatement],
    context: &[u8],
) -> Result<bool> {
    if proofs.len() != statements.len() {
        return Err(MentalPokerError::InvalidParameters(
            "proofs and statements must have the same length".to_string(),
        ));
    }

    if proofs.is_empty() {
        return Ok(true);
    }

    // Convert to the internal format
    let combined: Vec<_> = proofs
        .iter()
        .zip(statements.iter())
        .map(|(proof, (g, h, a, b))| {
            (
                g.clone(),
                h.clone(),
                a.clone(),
                b.clone(),
                proof.clone(),
                context.to_vec(),
            )
        })
        .collect();

    BatchVerifier::verify_chaum_pedersen_batch(&combined)
}

/// Batch verification utilities.
///
/// Batch verification can be more efficient than individual verification
/// when verifying multiple proofs of the same type.
pub struct BatchVerifier;

impl BatchVerifier {
    /// Batch verify multiple Schnorr proofs.
    ///
    /// Uses random linear combination for efficient batch verification.
    /// This is more efficient than verifying each proof individually.
    ///
    /// # Arguments
    /// * `proofs` - Vector of (public_key, proof, context) tuples
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_schnorr_batch(
        proofs: &[(PublicKey, KeyOwnershipProof, Vec<u8>)],
    ) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        // Generate random weights for each proof
        let weights: Vec<Felt> = proofs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"batch-weight-");
                hasher.update((i as u64).to_le_bytes());
                hasher.update(scalar::random_felt().to_bytes_be());
                let hash = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes[1..].copy_from_slice(&hash[..31]);
                Felt::from_bytes_be(&bytes)
            })
            .collect();

        let g = StarkCurve::GENERATOR;

        // Compute weighted sums for batch verification
        // Check: sum(w_i * g^s_i) = sum(w_i * (a_i + pk_i^c_i))
        let mut lhs_sum = ProjectivePoint::identity();
        let mut rhs_sum = ProjectivePoint::identity();

        for (i, (pk, proof, context)) in proofs.iter().enumerate() {
            // First verify the challenge matches
            let a = proof.commitment.to_projective()?;
            let s = Felt::from_hex(&proof.response)
                .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;
            let c = Felt::from_hex(&proof.challenge)
                .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;

            // Recompute challenge
            let a_affine = StarkCurve::projective_to_affine(&a)?;
            let pk_affine = StarkCurve::projective_to_affine(&pk.point)?;
            let g_affine = StarkCurve::projective_to_affine(&g)?;

            let mut challenge_input = Vec::new();
            let mut full_context = Vec::from(crate::protocol::KEY_OWNERSHIP_CONTEXT);
            full_context.extend_from_slice(context);
            challenge_input.extend_from_slice(&full_context);
            challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
            challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
            challenge_input.extend_from_slice(&pk_affine.x().to_bytes_be());
            challenge_input.extend_from_slice(&pk_affine.y().to_bytes_be());
            challenge_input.extend_from_slice(&a_affine.x().to_bytes_be());
            challenge_input.extend_from_slice(&a_affine.y().to_bytes_be());

            let c_computed = compute_challenge(&challenge_input);
            if c != c_computed {
                return Ok(false);
            }

            // Add weighted contribution to batch check
            // LHS: w * g^s
            let weighted_s = scalar::scalar_mul(&weights[i], &s)?;
            let lhs_term = StarkCurve::mul(&weighted_s, Some(&g));
            lhs_sum = StarkCurve::add(&lhs_sum, &lhs_term);

            // RHS: w * (a + pk^c)
            let pk_c = StarkCurve::mul(&c, Some(&pk.point));
            let rhs_unweighted = StarkCurve::add(&a, &pk_c);
            let rhs_term = StarkCurve::mul(&weights[i], Some(&rhs_unweighted));
            rhs_sum = StarkCurve::add(&rhs_sum, &rhs_term);
        }

        let lhs_affine = StarkCurve::projective_to_affine(&lhs_sum)?;
        let rhs_affine = StarkCurve::projective_to_affine(&rhs_sum)?;

        Ok(lhs_affine == rhs_affine)
    }

    /// Batch verify multiple DL equality proofs using random linear combinations.
    ///
    /// This is more efficient than verifying each proof individually when verifying
    /// multiple proofs. The batch verification uses random weights to combine all
    /// verification equations into a single multi-scalar multiplication check.
    ///
    /// # Algorithm
    /// For each Chaum-Pedersen proof, we need to verify two equations:
    /// 1. g^s = a1 * y1^c
    /// 2. h^s = a2 * y2^c
    ///
    /// For batch verification, we:
    /// 1. Verify all challenges are correctly computed (cannot batch this)
    /// 2. Generate random weights r_i for each proof
    /// 3. Combine verification equations with random linear combinations:
    ///    - sum(r_i * g_i^s_i) = sum(r_i * (a1_i + y1_i^c_i))
    ///    - sum(r_i * h_i^s_i) = sum(r_i * (a2_i + y2_i^c_i))
    ///
    /// If any proof is invalid, the combined check will fail with overwhelming
    /// probability (due to random weights).
    ///
    /// # Arguments
    /// * `proofs` - Vector of (g, h, y1, y2, proof, context) tuples
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_chaum_pedersen_batch(proofs: &[BatchVerificationInput]) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        // For single proof, just use regular verification (no benefit from batching)
        if proofs.len() == 1 {
            let (g, h, y1, y2, proof, context) = &proofs[0];
            return ChaumPedersenProtocol::verify(g, h, y1, y2, proof, context);
        }

        // Generate random weights for batch verification
        // We use a hash-based approach to derive deterministic weights from the proofs
        // This provides security against adaptive adversaries
        let weights = Self::generate_batch_weights(proofs);

        // Parse all proof components and verify challenges
        let mut parsed_proofs = Vec::with_capacity(proofs.len());
        for (g, h, y1, y2, proof, context) in proofs {
            let a1 = proof.a1.to_projective()?;
            let a2 = proof.a2.to_projective()?;
            let s = Felt::from_hex(&proof.response)
                .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;
            let c = Felt::from_hex(&proof.challenge)
                .map_err(|e| MentalPokerError::SerializationError(e.to_string()))?;

            // Verify the challenge is correctly computed (Fiat-Shamir)
            let c_computed =
                Self::compute_chaum_pedersen_challenge(g, h, y1, y2, &a1, &a2, context)?;
            if c != c_computed {
                return Ok(false);
            }

            parsed_proofs.push((g.clone(), h.clone(), y1.clone(), y2.clone(), a1, a2, s, c));
        }

        // Batch verify the two equations using random linear combinations
        // Equation 1: sum(r_i * g_i^s_i) = sum(r_i * (a1_i + y1_i^c_i))
        // Equation 2: sum(r_i * h_i^s_i) = sum(r_i * (a2_i + y2_i^c_i))

        let mut lhs1_sum = ProjectivePoint::identity();
        let mut rhs1_sum = ProjectivePoint::identity();
        let mut lhs2_sum = ProjectivePoint::identity();
        let mut rhs2_sum = ProjectivePoint::identity();

        for (i, (g, h, y1, y2, a1, a2, s, c)) in parsed_proofs.iter().enumerate() {
            let r_i = &weights[i];

            // Compute weighted scalar: r_i * s
            let weighted_s = scalar::scalar_mul(r_i, s)?;

            // LHS1: r_i * g^s = g^(r_i * s)
            let lhs1_term = StarkCurve::mul(&weighted_s, Some(g));
            lhs1_sum = StarkCurve::add(&lhs1_sum, &lhs1_term);

            // RHS1: r_i * (a1 + y1^c)
            let y1_c = StarkCurve::mul(c, Some(y1));
            let rhs1_unweighted = StarkCurve::add(a1, &y1_c);
            let rhs1_term = StarkCurve::mul(r_i, Some(&rhs1_unweighted));
            rhs1_sum = StarkCurve::add(&rhs1_sum, &rhs1_term);

            // LHS2: r_i * h^s = h^(r_i * s)
            let lhs2_term = StarkCurve::mul(&weighted_s, Some(h));
            lhs2_sum = StarkCurve::add(&lhs2_sum, &lhs2_term);

            // RHS2: r_i * (a2 + y2^c)
            let y2_c = StarkCurve::mul(c, Some(y2));
            let rhs2_unweighted = StarkCurve::add(a2, &y2_c);
            let rhs2_term = StarkCurve::mul(r_i, Some(&rhs2_unweighted));
            rhs2_sum = StarkCurve::add(&rhs2_sum, &rhs2_term);
        }

        // Check both equations
        let lhs1_affine = StarkCurve::projective_to_affine(&lhs1_sum)?;
        let rhs1_affine = StarkCurve::projective_to_affine(&rhs1_sum)?;
        if lhs1_affine != rhs1_affine {
            return Ok(false);
        }

        let lhs2_affine = StarkCurve::projective_to_affine(&lhs2_sum)?;
        let rhs2_affine = StarkCurve::projective_to_affine(&rhs2_sum)?;

        Ok(lhs2_affine == rhs2_affine)
    }

    /// Generate deterministic random weights for batch verification.
    ///
    /// Uses a hash-based approach to derive weights from all proof data,
    /// providing security against adaptive adversaries who might try to
    /// create proofs that cancel out in the batch check.
    fn generate_batch_weights(proofs: &[BatchVerificationInput]) -> Vec<Felt> {
        let mut weights = Vec::with_capacity(proofs.len());

        // Create a seed from all proof data
        let mut seed_hasher = sha2::Sha256::new();
        seed_hasher.update(b"chaum-pedersen-batch-weights");

        for (g, h, y1, y2, proof, context) in proofs {
            // Add all public data to the seed
            if let Ok(g_affine) = StarkCurve::projective_to_affine(g) {
                seed_hasher.update(g_affine.x().to_bytes_be());
                seed_hasher.update(g_affine.y().to_bytes_be());
            }
            if let Ok(h_affine) = StarkCurve::projective_to_affine(h) {
                seed_hasher.update(h_affine.x().to_bytes_be());
                seed_hasher.update(h_affine.y().to_bytes_be());
            }
            if let Ok(y1_affine) = StarkCurve::projective_to_affine(y1) {
                seed_hasher.update(y1_affine.x().to_bytes_be());
                seed_hasher.update(y1_affine.y().to_bytes_be());
            }
            if let Ok(y2_affine) = StarkCurve::projective_to_affine(y2) {
                seed_hasher.update(y2_affine.x().to_bytes_be());
                seed_hasher.update(y2_affine.y().to_bytes_be());
            }
            seed_hasher.update(&proof.response);
            seed_hasher.update(&proof.challenge);
            seed_hasher.update(context);
        }

        let seed = seed_hasher.finalize();

        // Generate a weight for each proof using the seed
        for i in 0..proofs.len() {
            let mut weight_hasher = sha2::Sha256::new();
            weight_hasher.update(b"weight-");
            weight_hasher.update((i as u64).to_le_bytes());
            weight_hasher.update(seed);
            let hash = weight_hasher.finalize();

            // Convert to Felt (use first 31 bytes to stay within field)
            let mut bytes = [0u8; 32];
            bytes[1..].copy_from_slice(&hash[..31]);
            weights.push(Felt::from_bytes_be(&bytes));
        }

        weights
    }

    /// Compute the Chaum-Pedersen challenge for verification.
    fn compute_chaum_pedersen_challenge(
        g: &ProjectivePoint,
        h: &ProjectivePoint,
        y1: &ProjectivePoint,
        y2: &ProjectivePoint,
        a1: &ProjectivePoint,
        a2: &ProjectivePoint,
        context: &[u8],
    ) -> Result<Felt> {
        let g_affine = StarkCurve::projective_to_affine(g)?;
        let h_affine = StarkCurve::projective_to_affine(h)?;
        let y1_affine = StarkCurve::projective_to_affine(y1)?;
        let y2_affine = StarkCurve::projective_to_affine(y2)?;
        let a1_affine = StarkCurve::projective_to_affine(a1)?;
        let a2_affine = StarkCurve::projective_to_affine(a2)?;

        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(context);
        challenge_input.extend_from_slice(&g_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&g_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&h_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&y2_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a1_affine.y().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.x().to_bytes_be());
        challenge_input.extend_from_slice(&a2_affine.y().to_bytes_be());

        Ok(compute_challenge(&challenge_input))
    }

    /// Batch verify multiple reveal token proofs.
    ///
    /// # Arguments
    /// * `proofs` - Vector of (masked_card, token, public_key, proof) tuples
    ///
    /// # Returns
    /// `Ok(true)` if all proofs are valid, `Ok(false)` if any is invalid.
    #[must_use = "verification result must be checked"]
    pub fn verify_reveal_tokens_batch(
        proofs: &[(
            crate::types::MaskedCard,
            crate::types::RevealToken,
            PublicKey,
            DLEqualityProof,
        )],
    ) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        let g = StarkCurve::GENERATOR;
        let context = crate::protocol::REVEAL_CONTEXT;

        // Convert to format for batch Chaum-Pedersen verification
        let cp_proofs: Vec<_> = proofs
            .iter()
            .map(|(masked, token, pk, proof)| {
                (
                    masked.c0.clone(),
                    g.clone(),
                    token.point.clone(),
                    pk.point.clone(),
                    proof.clone(),
                    context.to_vec(),
                )
            })
            .collect();

        Self::verify_chaum_pedersen_batch(&cp_proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_proof() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let context = b"test context";

        let proof = SchnorrProtocol::prove(&pk, &sk, context).unwrap();
        let valid = SchnorrProtocol::verify(&pk, &proof, context).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_schnorr_invalid_context() {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        let proof = SchnorrProtocol::prove(&pk, &sk, b"context1").unwrap();
        let valid = SchnorrProtocol::verify(&pk, &proof, b"context2").unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_schnorr_wrong_key() {
        let sk1 = SecretKey::random();
        let sk2 = SecretKey::random();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let context = b"test";

        let proof = SchnorrProtocol::prove(&pk1, &sk1, context).unwrap();
        let valid = SchnorrProtocol::verify(&pk2, &proof, context).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_chaum_pedersen_proof() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let x = scalar::random_felt();

        let y1 = StarkCurve::mul(&x, Some(&g));
        let y2 = StarkCurve::mul(&x, Some(&h));

        let context = b"chaum-pedersen test";
        let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
        let valid = ChaumPedersenProtocol::verify(&g, &h, &y1, &y2, &proof, context).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_chaum_pedersen_different_exponents() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let x1 = scalar::random_felt();
        let x2 = scalar::random_felt();

        let y1 = StarkCurve::mul(&x1, Some(&g));
        let y2 = StarkCurve::mul(&x2, Some(&h)); // Different exponent!

        let context = b"chaum-pedersen test";
        // This should still create a proof, but for the wrong statement
        let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x1, context).unwrap();
        let valid = ChaumPedersenProtocol::verify(&g, &h, &y1, &y2, &proof, context).unwrap();
        // Should fail because y2 != h^x1
        assert!(!valid);
    }

    // ==================== Batch Verification Tests ====================

    #[test]
    fn test_batch_verify_chaum_pedersen_empty() {
        let proofs: Vec<(
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            DLEqualityProof,
            Vec<u8>,
        )> = vec![];
        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(result, "Empty batch should verify as true");
    }

    #[test]
    fn test_batch_verify_chaum_pedersen_single() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let x = scalar::random_felt();

        let y1 = StarkCurve::mul(&x, Some(&g));
        let y2 = StarkCurve::mul(&x, Some(&h));

        let context = b"batch-single-test";
        let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();

        let proofs = vec![(g, h, y1, y2, proof, context.to_vec())];
        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(result, "Single valid proof should verify");
    }

    #[test]
    fn test_batch_verify_chaum_pedersen_multiple_valid() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"batch-multi-test";

        let mut proofs = Vec::new();

        // Create 5 valid proofs
        for _ in 0..5 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
            proofs.push((g.clone(), h.clone(), y1, y2, proof, context.to_vec()));
        }

        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(result, "Multiple valid proofs should verify");
    }

    #[test]
    fn test_batch_verify_chaum_pedersen_one_invalid() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"batch-invalid-test";

        let mut proofs = Vec::new();

        // Create 4 valid proofs
        for _ in 0..4 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
            proofs.push((g.clone(), h.clone(), y1, y2, proof, context.to_vec()));
        }

        // Create 1 invalid proof (different exponents)
        let x1 = scalar::random_felt();
        let x2 = scalar::random_felt();
        let y1 = StarkCurve::mul(&x1, Some(&g));
        let y2 = StarkCurve::mul(&x2, Some(&h)); // Different exponent!
        let invalid_proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x1, context).unwrap();
        proofs.push((
            g.clone(),
            h.clone(),
            y1,
            y2,
            invalid_proof,
            context.to_vec(),
        ));

        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(!result, "Batch with one invalid proof should fail");
    }

    #[test]
    fn test_batch_verify_chaum_pedersen_wrong_context() {
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let x = scalar::random_felt();

        let y1 = StarkCurve::mul(&x, Some(&g));
        let y2 = StarkCurve::mul(&x, Some(&h));

        // Prove with one context
        let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, b"context1").unwrap();

        // Verify with different context
        let proofs = vec![(g, h, y1, y2, proof, b"context2".to_vec())];
        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(!result, "Wrong context should fail verification");
    }

    #[test]
    fn test_batch_verify_matches_individual_verification() {
        // Test that batch verification gives the same result as individual verification
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"batch-vs-individual";

        let mut proofs = Vec::new();

        // Create 10 valid proofs
        for _ in 0..10 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
            proofs.push((g.clone(), h.clone(), y1, y2, proof, context.to_vec()));
        }

        // Verify individually
        let mut all_valid = true;
        for (g, h, y1, y2, proof, ctx) in &proofs {
            if !ChaumPedersenProtocol::verify(g, h, y1, y2, proof, ctx).unwrap() {
                all_valid = false;
                break;
            }
        }

        // Verify in batch
        let batch_result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();

        assert_eq!(
            all_valid, batch_result,
            "Batch verification should match individual verification"
        );
    }

    #[test]
    fn test_batch_verify_different_bases() {
        // Test batch verification with different g and h for each proof
        let context = b"different-bases-test";
        let mut proofs = Vec::new();

        for i in 1u64..5 {
            // Use different bases derived from scalars
            let g = StarkCurve::mul_generator(&Felt::from(i * 7));
            let h = StarkCurve::mul_generator(&Felt::from(i * 13));

            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));

            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
            proofs.push((g, h, y1, y2, proof, context.to_vec()));
        }

        let result = BatchVerifier::verify_chaum_pedersen_batch(&proofs).unwrap();
        assert!(
            result,
            "Batch verification with different bases should work"
        );
    }

    #[test]
    fn test_batch_verify_deterministic_weights() {
        // Test that the same proofs always generate the same weights
        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"deterministic-test";

        let mut proofs = Vec::new();
        for _ in 0..3 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();
            proofs.push((g.clone(), h.clone(), y1, y2, proof, context.to_vec()));
        }

        // Generate weights twice
        let weights1 = BatchVerifier::generate_batch_weights(&proofs);
        let weights2 = BatchVerifier::generate_batch_weights(&proofs);

        assert_eq!(
            weights1, weights2,
            "Weights should be deterministic for the same proofs"
        );
    }

    // ==================== Convenience API Tests ====================

    #[test]
    fn test_batch_verify_convenience_api() {
        use super::batch_verify_chaum_pedersen;

        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"convenience-api-test";

        let mut proofs_list = Vec::new();
        let mut statements = Vec::new();

        // Create 5 valid proofs
        for _ in 0..5 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();

            proofs_list.push(proof);
            statements.push((g.clone(), h.clone(), y1, y2));
        }

        let result = batch_verify_chaum_pedersen(&proofs_list, &statements, context).unwrap();
        assert!(result, "Convenience API should verify valid proofs");
    }

    #[test]
    fn test_batch_verify_convenience_api_mismatched_lengths() {
        use super::batch_verify_chaum_pedersen;

        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"mismatch-test";
        let x = scalar::random_felt();

        let y1 = StarkCurve::mul(&x, Some(&g));
        let y2 = StarkCurve::mul(&x, Some(&h));
        let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();

        // Different number of proofs and statements
        let proofs_list = vec![proof.clone(), proof];
        let statements = vec![(g, h, y1, y2)];

        let result = batch_verify_chaum_pedersen(&proofs_list, &statements, context);
        assert!(result.is_err(), "Mismatched lengths should return error");
    }

    #[test]
    fn test_batch_verify_convenience_api_empty() {
        use super::batch_verify_chaum_pedersen;

        let proofs_list: Vec<DLEqualityProof> = vec![];
        let statements: Vec<(
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
            ProjectivePoint,
        )> = vec![];
        let context = b"empty-test";

        let result = batch_verify_chaum_pedersen(&proofs_list, &statements, context).unwrap();
        assert!(result, "Empty batch should verify as true");
    }

    #[test]
    fn test_batch_verify_convenience_api_invalid_proof() {
        use super::batch_verify_chaum_pedersen;

        let g = StarkCurve::GENERATOR;
        let h = StarkCurve::GENERATOR_H;
        let context = b"invalid-proof-test";

        let mut proofs_list = Vec::new();
        let mut statements = Vec::new();

        // Create 2 valid proofs
        for _ in 0..2 {
            let x = scalar::random_felt();
            let y1 = StarkCurve::mul(&x, Some(&g));
            let y2 = StarkCurve::mul(&x, Some(&h));
            let proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x, context).unwrap();

            proofs_list.push(proof);
            statements.push((g.clone(), h.clone(), y1, y2));
        }

        // Create 1 invalid proof
        let x1 = scalar::random_felt();
        let x2 = scalar::random_felt();
        let y1 = StarkCurve::mul(&x1, Some(&g));
        let y2 = StarkCurve::mul(&x2, Some(&h)); // Different exponent!
        let invalid_proof = ChaumPedersenProtocol::prove(&g, &h, &y1, &y2, &x1, context).unwrap();

        proofs_list.push(invalid_proof);
        statements.push((g.clone(), h.clone(), y1, y2));

        let result = batch_verify_chaum_pedersen(&proofs_list, &statements, context).unwrap();
        assert!(!result, "Batch with invalid proof should fail");
    }
}
