//! ElGamal encryption with zero-knowledge proofs.

use crate::curve::StarkCurve;
use crate::hash::compute_challenge_triple;
use crate::scalar;
use krusty_kms_common::{ElGamalCiphertext, ElGamalProof, Result, SecretFelt, SerializablePoint};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// ElGamal encryption ciphertext with proof.
pub struct ElGamalEncryption {
    pub l: ProjectivePoint,
    pub r: ProjectivePoint,
    pub proof: ElGamalProof,
}

/// ElGamal encryption scheme on the Stark curve.
pub struct ElGamal;

impl ElGamal {
    /// Encrypt a message with a public key and generate a zero-knowledge proof.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (as scalar)
    /// * `public_key` - The recipient's public key
    /// * `random` - Random blinding factor
    /// * `prefix` - Fiat-Shamir prefix
    ///
    /// # Returns
    /// ElGamalEncryption containing ciphertext (L, R) and proof
    ///
    /// # Cyclomatic Complexity: 1
    pub fn encrypt(
        message: &Felt,
        public_key: &ProjectivePoint,
        random: &Felt,
        prefix: &Felt,
    ) -> Result<ElGamalEncryption> {
        let g = StarkCurve::generator();

        // Compute ciphertext: L = g^m + pk^r, R = g^r (Tongo standard format)
        let g_m = StarkCurve::mul(message, Some(&g));
        let pk_r = StarkCurve::mul(random, Some(public_key));
        let l = StarkCurve::add(&g_m, &pk_r); // L = g^m + pk^r (ciphertext)
        let r = StarkCurve::mul(random, Some(&g)); // R = g^r (randomness)

        // Generate proof of correct encryption
        let proof = Self::prove_encryption(message, random, public_key, &l, &r, prefix, false)?;

        Ok(ElGamalEncryption { l, r, proof })
    }

    /// Encrypt with a fully transcript-bound Fiat-Shamir proof.
    ///
    /// Unlike [`ElGamal::encrypt`], the challenge is computed over the full
    /// statement and commitment set: `c = H(prefix, pk, L, R, AL, AR)`. This
    /// removes the legacy transcript's degree of freedom where the `AR`
    /// commitment is chosen after the challenge is known (the `R`-leg equation
    /// `g^sr = AR + R^c` is satisfiable for *any* `c` when `AR` is not bound).
    ///
    /// # Compatibility
    ///
    /// The resulting proofs are NOT accepted by verifiers pinned to the legacy
    /// transcript (`H(prefix, L, R, AL)`), including any deployed Cairo
    /// verifier. Use this only for off-chain verification or new contracts.
    ///
    /// # Cyclomatic Complexity: 1
    pub fn encrypt_strong(
        message: &Felt,
        public_key: &ProjectivePoint,
        random: &Felt,
        prefix: &Felt,
    ) -> Result<ElGamalEncryption> {
        let g = StarkCurve::generator();

        let g_m = StarkCurve::mul(message, Some(&g));
        let pk_r = StarkCurve::mul(random, Some(public_key));
        let l = StarkCurve::add(&g_m, &pk_r);
        let r = StarkCurve::mul(random, Some(&g));

        let proof = Self::prove_encryption(message, random, public_key, &l, &r, prefix, true)?;

        Ok(ElGamalEncryption { l, r, proof })
    }

    /// Generate a proof that (L, R) is a valid ElGamal encryption.
    ///
    /// Proves knowledge of (m, r) such that:
    /// - L = g^m + pk^r (ciphertext)
    /// - R = g^r (randomness)
    ///
    /// When `strong_transcript` is false the legacy challenge
    /// `H(prefix, L, R, AL)` is used; when true the challenge additionally binds
    /// the public key and the `AR` commitment: `H(prefix, pk, L, R, AL, AR)`.
    ///
    /// # Cyclomatic Complexity: 2
    fn prove_encryption(
        message: &Felt,
        random: &Felt,
        public_key: &ProjectivePoint,
        l: &ProjectivePoint,
        r: &ProjectivePoint,
        prefix: &Felt,
        strong_transcript: bool,
    ) -> Result<ElGamalProof> {
        let g = StarkCurve::generator();

        // Generate random blinding factors (wrapped in SecretFelt for zeroization on drop)
        let r_b = SecretFelt::new(crate::scalar::random_felt());
        let r_r = SecretFelt::new(crate::scalar::random_felt());

        // Compute commitments (matching corrected L/R format)
        // AL = g^r_b + pk^r_r (commitment for L = g^m + pk^r)
        // AR = g^r_r (commitment for R = g^r)
        let g_rb = StarkCurve::mul(r_b.expose_secret(), Some(&g));
        let pk_rr = StarkCurve::mul(r_r.expose_secret(), Some(public_key));
        let a_l = StarkCurve::add(&g_rb, &pk_rr);
        let a_r = StarkCurve::mul(r_r.expose_secret(), Some(&g));

        // Compute Fiat-Shamir challenge.
        //
        // SECURITY / COMPATIBILITY: the legacy shape omits `pk` and `AR` from
        // the challenge hash to preserve compatibility with existing verifiers
        // / vectors. The strong shape binds the full statement and both
        // commitments; `AR` is a prover-generated commitment and therefore
        // cannot be folded into the caller-supplied `prefix` instead.
        let c = if strong_transcript {
            crate::hash::compute_challenge(prefix, &[public_key, l, r, &a_l, &a_r])?
        } else {
            compute_challenge_triple(prefix, l, r, &a_l)?
        };

        // Compute responses (mod curve order)
        let c_message = scalar::scalar_mul(&c, message)?;
        let s_b = scalar::scalar_add(r_b.expose_secret(), &c_message)?;
        let c_random = scalar::scalar_mul(&c, random)?;
        let s_r = scalar::scalar_add(r_r.expose_secret(), &c_random)?;

        Ok(ElGamalProof {
            al: SerializablePoint::try_from_projective(&a_l)?,
            ar: SerializablePoint::try_from_projective(&a_r)?,
            sb: s_b,
            sr: s_r,
            c,
        })
    }

    /// Verify an ElGamal encryption proof against the legacy transcript
    /// `H(prefix, L, R, AL)`.
    ///
    /// Prefer [`ElGamal::verify_strong`] whenever the verifier is not pinned to
    /// the legacy transcript by an existing deployment.
    ///
    /// # Cyclomatic Complexity: 2
    pub fn verify(
        l: &ProjectivePoint,
        r: &ProjectivePoint,
        public_key: &ProjectivePoint,
        proof: &ElGamalProof,
        prefix: &Felt,
    ) -> Result<bool> {
        Self::verify_inner(l, r, public_key, proof, prefix, false)
    }

    /// Verify an ElGamal encryption proof against the strong transcript
    /// `H(prefix, pk, L, R, AL, AR)`.
    ///
    /// Only accepts proofs produced by [`ElGamal::encrypt_strong`]; legacy
    /// proofs are rejected because their challenge does not commit to `pk`/`AR`.
    ///
    /// # Cyclomatic Complexity: 2
    pub fn verify_strong(
        l: &ProjectivePoint,
        r: &ProjectivePoint,
        public_key: &ProjectivePoint,
        proof: &ElGamalProof,
        prefix: &Felt,
    ) -> Result<bool> {
        Self::verify_inner(l, r, public_key, proof, prefix, true)
    }

    /// Shared verification: recompute the challenge under the requested
    /// transcript, then check both POE equations.
    ///
    /// # Cyclomatic Complexity: 3
    fn verify_inner(
        l: &ProjectivePoint,
        r: &ProjectivePoint,
        public_key: &ProjectivePoint,
        proof: &ElGamalProof,
        prefix: &Felt,
        strong_transcript: bool,
    ) -> Result<bool> {
        let g = StarkCurve::generator();

        // Parse proof components
        let a_l = proof.al.to_affine()?;
        let a_r = proof.ar.to_affine()?;
        let a_l_proj = StarkCurve::affine_to_projective(&a_l);
        let a_r_proj = StarkCurve::affine_to_projective(&a_r);
        let s_b = proof.sb;
        let s_r = proof.sr;
        let c = proof.c;

        // Recompute challenge
        let c_computed = if strong_transcript {
            crate::hash::compute_challenge(prefix, &[public_key, l, r, &a_l_proj, &a_r_proj])?
        } else {
            compute_challenge_triple(prefix, l, r, &a_l_proj)?
        };
        if c != c_computed {
            return Ok(false);
        }

        // Verify first equation (POE for R): g^sr = AR * R^c
        let lhs1 = StarkCurve::mul(&s_r, Some(&g));
        let r_c = StarkCurve::mul(&c, Some(r));
        let rhs1 = StarkCurve::add(&a_r_proj, &r_c);

        let lhs1_affine = StarkCurve::projective_to_affine(&lhs1)?;
        let rhs1_affine = StarkCurve::projective_to_affine(&rhs1)?;

        if lhs1_affine != rhs1_affine {
            return Ok(false);
        }

        // Verify second equation (POE2 for L): g^sb * pk^sr = AL * L^c
        let g_sb = StarkCurve::mul(&s_b, Some(&g));
        let pk_sr = StarkCurve::mul(&s_r, Some(public_key));
        let lhs2 = StarkCurve::add(&g_sb, &pk_sr);
        let l_c = StarkCurve::mul(&c, Some(l));
        let rhs2 = StarkCurve::add(&a_l_proj, &l_c);

        let lhs2_affine = StarkCurve::projective_to_affine(&lhs2)?;
        let rhs2_affine = StarkCurve::projective_to_affine(&rhs2)?;

        Ok(lhs2_affine == rhs2_affine)
    }

    /// Decrypt an ElGamal ciphertext.
    ///
    /// # Arguments
    /// * `ciphertext` - The ElGamal ciphertext (L, R)
    /// * `private_key` - The recipient's private key
    ///
    /// # Returns
    /// The decrypted message point (g^m)
    ///
    /// # Cyclomatic Complexity: 1
    pub fn decrypt(ciphertext: &ElGamalCiphertext, private_key: &Felt) -> Result<ProjectivePoint> {
        // Compute sk * R where R = g^r
        // This gives us (sk*r)*g
        let r_sk = StarkCurve::mul(private_key, Some(&ciphertext.r));

        if r_sk.to_affine().is_err() {
            return Ok(ciphertext.l.clone());
        }

        // Compute L - sk*R = g^m
        // L = (m + r*sk)*g, sk*R = (sk*r)*g
        // L - sk*R = (m + r*sk)*g - (sk*r)*g = m*g
        // Note: In projective coordinates, subtraction is adding the negation
        let r_sk_affine = StarkCurve::projective_to_affine(&r_sk)?;
        let neg_r_sk = StarkCurve::affine_to_projective(&create_affine_point(
            r_sk_affine.x(),
            -r_sk_affine.y(),
        )?);

        let message_point = StarkCurve::add(&ciphertext.l, &neg_r_sk);
        Ok(message_point)
    }

    /// Decrypt an ElGamal ciphertext and recover a small integer plaintext.
    ///
    /// # Arguments
    /// * `ciphertext` - The ElGamal ciphertext (L, R)
    /// * `private_key` - The recipient's private key
    /// * `max_search` - Maximum plaintext value to search for
    ///
    /// # Returns
    /// The recovered plaintext if it is within `max_search`
    pub fn decrypt_balance_with_limit(
        ciphertext: &ElGamalCiphertext,
        private_key: &Felt,
        max_search: u128,
    ) -> Result<u128> {
        let message_point = Self::decrypt(ciphertext, private_key)?;
        recover_small_discrete_log(&message_point, max_search)
    }
}

use starknet_types_core::curve::AffinePoint;

fn create_affine_point(x: Felt, y: Felt) -> Result<AffinePoint> {
    AffinePoint::new(x, y).map_err(|e| {
        krusty_kms_common::KmsError::InvalidPublicKey(format!("Invalid affine point: {:?}", e))
    })
}

/// Recover a small discrete logarithm `m` from a point `g^m`.
pub fn recover_small_discrete_log(point: &ProjectivePoint, max_search: u128) -> Result<u128> {
    let generator = StarkCurve::generator();

    if point.to_affine().is_err() {
        return Ok(0);
    }

    let target_affine = StarkCurve::projective_to_affine(point)?;
    let mut current = generator.clone();
    for value in 1..=max_search {
        if StarkCurve::projective_to_affine(&current)? == target_affine {
            return Ok(value);
        }
        current = StarkCurve::add(&current, &generator);
    }

    Err(krusty_kms_common::KmsError::CryptoError(format!(
        "Failed to recover balance within search limit of {max_search}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn negate_point(p: &ProjectivePoint) -> ProjectivePoint {
        let affine = StarkCurve::projective_to_affine(p).unwrap();
        StarkCurve::affine_to_projective(&create_affine_point(affine.x(), -affine.y()).unwrap())
    }

    #[test]
    fn test_elgamal_encrypt_decrypt() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        // Verify proof
        let valid = ElGamal::verify(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(valid);

        // Decrypt
        let ciphertext = ElGamalCiphertext {
            l: encryption.l,
            r: encryption.r,
        };
        let decrypted = ElGamal::decrypt(&ciphertext, &sk).unwrap();
        let expected = StarkCurve::mul_generator(&message);

        let dec_affine = StarkCurve::projective_to_affine(&decrypted).unwrap();
        let exp_affine = StarkCurve::projective_to_affine(&expected).unwrap();

        assert_eq!(dec_affine, exp_affine);
    }

    #[test]
    fn test_elgamal_invalid_proof() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        // Tamper with proof
        encryption.proof.sb = Felt::from(1u64);

        let valid = ElGamal::verify(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_elgamal_verify_invalid_challenge() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        // Tamper with challenge - this should fail challenge verification
        encryption.proof.c = Felt::from(999999u64);

        let valid = ElGamal::verify(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_elgamal_verify_invalid_sr() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let mut encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        // Tamper with s_r - this should fail the first equation check
        encryption.proof.sr = Felt::from(1u64);

        let valid = ElGamal::verify(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_elgamal_decrypt_zero_message() {
        // Encrypt 0
        let message = Felt::ZERO;
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let encryption = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();

        let ciphertext = ElGamalCiphertext {
            l: encryption.l,
            r: encryption.r,
        };
        let decrypted = ElGamal::decrypt(&ciphertext, &sk).unwrap();

        // g^0 should be identity or special case
        // Due to the scalar mul implementation, 0 * g = identity
        let expected = StarkCurve::mul_generator(&message);
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn test_elgamal_strong_roundtrip() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();

        let valid = ElGamal::verify_strong(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(valid);

        // Strong proofs must not verify under the legacy transcript and vice versa.
        let legacy_valid = ElGamal::verify(
            &encryption.l,
            &encryption.r,
            &pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(!legacy_valid);

        let legacy = ElGamal::encrypt(&message, &pk, &random, &prefix).unwrap();
        let strong_accepts_legacy =
            ElGamal::verify_strong(&legacy.l, &legacy.r, &pk, &legacy.proof, &prefix).unwrap();
        assert!(!strong_accepts_legacy);
    }

    #[test]
    fn test_elgamal_strong_binds_ar_to_challenge() {
        // Attack recipe enabled by the legacy transcript's missing AR binding:
        // for ANY chosen challenge c and responses (s_b, s_r), setting
        //   AR = g^s_r - R^c        satisfies the R-leg equation, and
        //   AL = g^s_b + pk^s_r - L^c satisfies the L-leg equation.
        // Under the legacy transcript the attacker can shop for (s_b, s_r)
        // until H(prefix, L, R, AL) lands on the pre-chosen c is infeasible,
        // but the R-leg remains satisfiable for arbitrary c. Under the strong
        // transcript the crafted AR changes the challenge itself, so the
        // pre-chosen c never matches and the proof is rejected outright.
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();
        let g = StarkCurve::generator();

        // Attacker-chosen challenge and responses.
        let c_forged = Felt::from(31337u64);
        let s_b = Felt::from(111u64);
        let s_r = Felt::from(222u64);

        let r_c = StarkCurve::mul(&c_forged, Some(&encryption.r));
        let neg_r_c = negate_point(&r_c);
        let g_sr = StarkCurve::mul(&s_r, Some(&g));
        let ar_forged = StarkCurve::add(&g_sr, &neg_r_c);

        let l_c = StarkCurve::mul(&c_forged, Some(&encryption.l));
        let neg_l_c = negate_point(&l_c);
        let g_sb = StarkCurve::mul(&s_b, Some(&g));
        let pk_sr = StarkCurve::mul(&s_r, Some(&pk));
        let al_forged = StarkCurve::add(&StarkCurve::add(&g_sb, &pk_sr), &neg_l_c);

        let forged_proof = ElGamalProof {
            al: SerializablePoint::try_from_projective(&al_forged).unwrap(),
            ar: SerializablePoint::try_from_projective(&ar_forged).unwrap(),
            sb: s_b,
            sr: s_r,
            c: c_forged,
        };

        let valid =
            ElGamal::verify_strong(&encryption.l, &encryption.r, &pk, &forged_proof, &prefix)
                .unwrap();
        assert!(!valid, "strong transcript must reject after-the-fact AR");
    }

    #[test]
    fn test_elgamal_strong_challenge_changes_with_ar_and_pk() {
        let message = Felt::from(10u64);
        let sk = Felt::from(42u64);
        let pk = StarkCurve::mul_generator(&sk);
        let other_pk = StarkCurve::mul_generator(&Felt::from(7u64));
        let random = Felt::from(999u64);
        let prefix = Felt::from(42u64);

        let encryption = ElGamal::encrypt_strong(&message, &pk, &random, &prefix).unwrap();

        // Same proof under a different public key must not verify: pk is part
        // of the strong transcript.
        let valid = ElGamal::verify_strong(
            &encryption.l,
            &encryption.r,
            &other_pk,
            &encryption.proof,
            &prefix,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_elgamal_decrypt_zero_private_key_uses_identity_shared_secret() {
        let generator = StarkCurve::generator();
        let plaintext = Felt::from(7u64);
        let random = Felt::from(999u64);
        let ciphertext = ElGamalCiphertext {
            l: StarkCurve::mul(&plaintext, Some(&generator)),
            r: StarkCurve::mul(&random, Some(&generator)),
        };

        let decrypted = ElGamal::decrypt(&ciphertext, &Felt::ZERO).unwrap();
        let expected = StarkCurve::mul(&plaintext, Some(&generator));
        assert_eq!(decrypted, expected);
    }
}
