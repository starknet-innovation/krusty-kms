//! Audit proof protocol (SameEncryptUnknownRandom).
//!
//! Proves that two ElGamal ciphertexts encrypt the same plaintext,
//! where the prover knows the plaintext and private key but the verifier
//! doesn't know the random values used in the encryptions.

use crate::curve::StarkCurve;
use crate::hash::{compute_poseidon_challenge, poseidon_hash_many};
use crate::scalar;
use krusty_kms_common::{AuditProof, ElGamalCiphertext, Result, SecretFelt, SerializablePoint};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Cairo string 'audit' = 418581342580
const AUDIT_CAIRO_STRING: u64 = 418_581_342_580;

/// Data needed for computing the audit proof prefix (matching Cairo contract).
///
/// The contract computes the audit prefix as:
/// `poseidon_hash(chain_id, tongo_address, sender_address, 'audit', y.x, y.y,
///  auditor.x, auditor.y, storedL.x, storedL.y, storedR.x, storedR.y,
///  auditL.x, auditL.y, auditR.x, auditR.y)`
pub struct AuditPrefixData {
    pub chain_id: Felt,
    pub tongo_address: Felt,
    pub sender_address: Felt,
    pub user_pub_key: ProjectivePoint,
}

/// Generate an audit proof showing that two ciphertexts encrypt the same value.
///
/// This implements the SameEncryptUnknownRandom protocol which proves:
/// - The prover knows the private key x (for public key y = g^x)
/// - Both cipher0 and cipher1 encrypt the same balance b
/// - cipher0 = (g^b * y^r0, g^r0) under public key y
/// - cipher1 = (g^b * auditor^r1, g^r1) under auditor public key
///
/// Reference: typescript-reference/tongo-sdk/src/provers/audit.ts
pub struct AuditProver;

impl AuditProver {
    /// Generate a random scalar.
    fn random_felt() -> Felt {
        let mut bytes = [0u8; 32];
        crate::random::fill_random_bytes(&mut bytes);
        bytes[0] &= 0x0F; // Ensure it's in field
        Felt::from_bytes_be(&bytes)
    }

    /// Prove that cipher0 and cipher1 encrypt the same balance.
    ///
    /// # Arguments
    /// * `private_key` - User's private key x
    /// * `balance` - The plaintext balance being encrypted
    /// * `cipher0` - First ciphertext (stored balance) encrypted under user's public key
    /// * `auditor_pub_key` - Auditor's public key
    ///
    /// # Returns
    /// Tuple of (audit proof, audit ciphertext for the auditor)
    pub fn prove(
        private_key: &Felt,
        balance: u128,
        cipher0: &ElGamalCiphertext,
        auditor_pub_key: &ProjectivePoint,
        prefix_data: Option<&AuditPrefixData>,
    ) -> Result<(AuditProof, ElGamalCiphertext)> {
        Self::prove_with_validation(
            private_key,
            balance,
            cipher0,
            auditor_pub_key,
            true,
            prefix_data,
        )
    }

    /// Generate an audit proof with optional cipher validation.
    ///
    /// Set `validate` to false when using ciphers computed by subtraction (e.g., in transfer operations),
    /// as these may not pass the standard encryption validation check locally but will verify correctly on-chain.
    pub fn prove_with_validation(
        private_key: &Felt,
        balance: u128,
        cipher0: &ElGamalCiphertext,
        auditor_pub_key: &ProjectivePoint,
        validate: bool,
        prefix_data: Option<&AuditPrefixData>,
    ) -> Result<(AuditProof, ElGamalCiphertext)> {
        let g = StarkCurve::generator();

        // Validate input points
        if StarkCurve::is_infinity(&cipher0.l) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "cipher0.l is point at infinity".to_string(),
            ));
        }
        if StarkCurve::is_infinity(&cipher0.r) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "cipher0.r is point at infinity".to_string(),
            ));
        }
        if StarkCurve::is_infinity(auditor_pub_key) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "auditor_pub_key is point at infinity".to_string(),
            ));
        }

        // Optionally verify that cipher0 is a valid encryption of balance
        // Skip this check for ciphers computed by subtraction (transfer case)
        if validate {
            let r0_x = StarkCurve::mul(private_key, Some(&cipher0.r));
            let g_b_computed = &cipher0.l - &r0_x;
            let g_b_expected = StarkCurve::mul(&Felt::from(balance), Some(&g));

            if g_b_computed != g_b_expected {
                return Err(krusty_kms_common::KmsError::CryptoError(
                    "cipher0 is not a valid encryption of the balance".to_string(),
                ));
            }
        }

        // Generate random value for audit encryption (wrapped in SecretFelt for zeroization on drop)
        let r1 = SecretFelt::new(Self::random_felt());

        // Create cipher1 (audit balance encrypted under auditor's key)
        // L1 = g^balance * auditor^r1
        // R1 = g^r1
        //
        // Special case for balance=0 due to Rust curve implementation:
        // - Cairo: g^0 = O (point at infinity), so L1 = O + auditor^r1 = auditor^r1
        // - Rust: g^0 = g (bug), so we manually set L1 = auditor^r1 when balance=0
        let auditor_r1 = StarkCurve::mul(r1.expose_secret(), Some(auditor_pub_key));
        let l1 = if balance == 0 {
            // For balance=0: L1 = auditor^r1 (skip g^0 to avoid Rust curve bug)
            auditor_r1.clone()
        } else {
            // For balance>0: L1 = g^balance + auditor^r1
            let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
            StarkCurve::add(&g_b, &auditor_r1)
        };
        let r1_point = StarkCurve::mul(r1.expose_secret(), Some(&g));

        // Validate cipher1 points
        if StarkCurve::is_infinity(&l1) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "cipher1.l is point at infinity".to_string(),
            ));
        }
        if StarkCurve::is_infinity(&r1_point) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "cipher1.r is point at infinity".to_string(),
            ));
        }

        let cipher1 = ElGamalCiphertext { l: l1, r: r1_point };

        // Generate random blinding factors (wrapped in SecretFelt for zeroization on drop)
        let kx = SecretFelt::new(Self::random_felt());
        let kb = SecretFelt::new(Self::random_felt());
        let kr = SecretFelt::new(Self::random_felt());

        // Compute commitments
        // Ax = g^kx
        let ax = StarkCurve::mul(kx.expose_secret(), Some(&g));
        if StarkCurve::is_infinity(&ax) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "Ax is point at infinity".to_string(),
            ));
        }

        // AL0 = g^kb + R0^kx
        let g_kb = StarkCurve::mul(kb.expose_secret(), Some(&g));
        let r0_kx = StarkCurve::mul(kx.expose_secret(), Some(&cipher0.r));
        let al0 = StarkCurve::add(&g_kb, &r0_kx);
        if StarkCurve::is_infinity(&al0) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "AL0 is point at infinity".to_string(),
            ));
        }

        // AR1 = g^kr
        let ar1 = StarkCurve::mul(kr.expose_secret(), Some(&g));
        if StarkCurve::is_infinity(&ar1) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "AR1 is point at infinity".to_string(),
            ));
        }

        // AL1 = g^kb + auditor^kr
        let auditor_kr = StarkCurve::mul(kr.expose_secret(), Some(auditor_pub_key));
        let al1 = StarkCurve::add(&g_kb, &auditor_kr);
        if StarkCurve::is_infinity(&al1) {
            return Err(krusty_kms_common::KmsError::CryptoError(
                "AL1 is point at infinity".to_string(),
            ));
        }

        // Compute Fiat-Shamir challenge
        // When prefix_data is provided, compute the full prefix as the contract does:
        // prefix = poseidon_hash(chain_id, tongo_addr, sender_addr, 'audit', y.x, y.y,
        //          auditor.x, auditor.y, storedL.x, storedL.y, storedR.x, storedR.y,
        //          auditL.x, auditL.y, auditR.x, auditR.y)
        // challenge = reduce_modulo_order(poseidon_hash(prefix, Ax.x, Ax.y, AL0.x, AL0.y, AL1.x, AL1.y, AR1.x, AR1.y))
        let computed_prefix = if let Some(pd) = prefix_data {
            let user_affine = pd
                .user_pub_key
                .to_affine()
                .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;
            let auditor_affine = auditor_pub_key
                .to_affine()
                .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;
            let c0_l_affine = cipher0.l.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher0.l affine conversion failed".to_string(),
                )
            })?;
            let c0_r_affine = cipher0.r.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher0.r affine conversion failed".to_string(),
                )
            })?;
            let c1_l_affine = cipher1.l.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher1.l affine conversion failed".to_string(),
                )
            })?;
            let c1_r_affine = cipher1.r.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher1.r affine conversion failed".to_string(),
                )
            })?;

            poseidon_hash_many(&[
                pd.chain_id,
                pd.tongo_address,
                pd.sender_address,
                Felt::from(AUDIT_CAIRO_STRING),
                user_affine.x(),
                user_affine.y(),
                auditor_affine.x(),
                auditor_affine.y(),
                c0_l_affine.x(),
                c0_l_affine.y(),
                c0_r_affine.x(),
                c0_r_affine.y(),
                c1_l_affine.x(),
                c1_l_affine.y(),
                c1_r_affine.x(),
                c1_r_affine.y(),
            ])
        } else {
            Felt::from(AUDIT_CAIRO_STRING)
        };
        let c = compute_poseidon_challenge(&computed_prefix, &[&ax, &al0, &al1, &ar1])?;

        // Compute responses
        // sx = kx + c*x
        let c_x = scalar::scalar_mul(&c, private_key)?;
        let sx = scalar::scalar_add(kx.expose_secret(), &c_x)?;

        // sb = kb + c*balance
        let balance_felt = Felt::from(balance);
        let c_b = scalar::scalar_mul(&c, &balance_felt)?;
        let sb = scalar::scalar_add(kb.expose_secret(), &c_b)?;

        // sr = kr + c*r1
        let c_r1 = scalar::scalar_mul(&c, r1.expose_secret())?;
        let sr = scalar::scalar_add(kr.expose_secret(), &c_r1)?;

        // Serialize the proof
        let proof = AuditProof {
            ax: SerializablePoint::try_from_projective(&ax)?,
            al0: SerializablePoint::try_from_projective(&al0)?,
            al1: SerializablePoint::try_from_projective(&al1)?,
            ar1: SerializablePoint::try_from_projective(&ar1)?,
            sx,
            sb,
            sr,
            c,
        };

        Ok((proof, cipher1))
    }

    /// Verify an audit proof.
    ///
    /// # Arguments
    /// * `proof` - The audit proof to verify
    /// * `user_pub_key` - User's public key y = g^x
    /// * `cipher0` - First ciphertext (stored balance)
    /// * `cipher1` - Second ciphertext (audit balance)
    /// * `auditor_pub_key` - Auditor's public key
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    #[allow(dead_code)]
    pub fn verify(
        proof: &AuditProof,
        user_pub_key: &ProjectivePoint,
        cipher0: &ElGamalCiphertext,
        cipher1: &ElGamalCiphertext,
        auditor_pub_key: &ProjectivePoint,
        prefix_data: Option<&AuditPrefixData>,
    ) -> Result<bool> {
        let g = StarkCurve::generator();

        // Deserialize proof points
        let ax = StarkCurve::affine_to_projective(&proof.ax.to_affine()?);
        let al0 = StarkCurve::affine_to_projective(&proof.al0.to_affine()?);
        let al1 = StarkCurve::affine_to_projective(&proof.al1.to_affine()?);
        let ar1 = StarkCurve::affine_to_projective(&proof.ar1.to_affine()?);

        // Deserialize scalars
        let sx = proof.sx;
        let sb = proof.sb;
        let sr = proof.sr;
        let c = proof.c;

        // Recompute challenge with full prefix if prefix_data is provided
        let computed_prefix = if let Some(pd) = prefix_data {
            let user_affine = pd
                .user_pub_key
                .to_affine()
                .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;
            let auditor_affine = auditor_pub_key
                .to_affine()
                .map_err(|_| krusty_kms_common::KmsError::PointAtInfinity)?;
            let c0_l_affine = cipher0.l.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher0.l affine conversion failed".to_string(),
                )
            })?;
            let c0_r_affine = cipher0.r.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher0.r affine conversion failed".to_string(),
                )
            })?;
            let c1_l_affine = cipher1.l.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher1.l affine conversion failed".to_string(),
                )
            })?;
            let c1_r_affine = cipher1.r.to_affine().map_err(|_| {
                krusty_kms_common::KmsError::CryptoError(
                    "cipher1.r affine conversion failed".to_string(),
                )
            })?;

            poseidon_hash_many(&[
                pd.chain_id,
                pd.tongo_address,
                pd.sender_address,
                Felt::from(AUDIT_CAIRO_STRING),
                user_affine.x(),
                user_affine.y(),
                auditor_affine.x(),
                auditor_affine.y(),
                c0_l_affine.x(),
                c0_l_affine.y(),
                c0_r_affine.x(),
                c0_r_affine.y(),
                c1_l_affine.x(),
                c1_l_affine.y(),
                c1_r_affine.x(),
                c1_r_affine.y(),
            ])
        } else {
            Felt::from(AUDIT_CAIRO_STRING)
        };
        let c_computed = compute_poseidon_challenge(&computed_prefix, &[&ax, &al0, &al1, &ar1])?;
        if c != c_computed {
            return Ok(false);
        }

        // Verify equations:
        // 1. g^sx = Ax + y^c
        let lhs1 = StarkCurve::mul(&sx, Some(&g));
        let y_c = StarkCurve::mul(&c, Some(user_pub_key));
        let rhs1 = StarkCurve::add(&ax, &y_c);
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // 2. g^sb + R0^sx = AL0 + c*L0
        let g_sb = StarkCurve::mul(&sb, Some(&g));
        let r0_sx = StarkCurve::mul(&sx, Some(&cipher0.r));
        let lhs2 = StarkCurve::add(&g_sb, &r0_sx);

        let c_l0 = StarkCurve::mul(&c, Some(&cipher0.l));
        let rhs2 = StarkCurve::add(&al0, &c_l0);
        if lhs2 != rhs2 {
            return Ok(false);
        }

        // 3. g^sr = AR1 + R1^c
        let lhs3 = StarkCurve::mul(&sr, Some(&g));
        let r1_c = StarkCurve::mul(&c, Some(&cipher1.r));
        let rhs3 = StarkCurve::add(&ar1, &r1_c);
        if lhs3 != rhs3 {
            return Ok(false);
        }

        // 4. g^sb + auditor^sr = AL1 + c*L1
        let auditor_sr = StarkCurve::mul(&sr, Some(auditor_pub_key));
        let lhs4 = StarkCurve::add(&g_sb, &auditor_sr);

        let c_l1 = StarkCurve::mul(&c, Some(&cipher1.l));
        let rhs4 = StarkCurve::add(&al1, &c_l1);
        if lhs4 != rhs4 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_prove_and_verify() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create cipher0 (stored balance encrypted under user's key)
        let r0 = Felt::from(98765u64);
        let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        // Create auditor key
        let auditor_private = Felt::from(99999u64);
        let auditor_pub_key = StarkCurve::mul(&auditor_private, Some(&g));

        // Generate proof (this also creates cipher1)
        let (proof, cipher1) =
            AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None)
                .expect("proof generation should succeed");

        // Verify proof
        let is_valid = AuditProver::verify(
            &proof,
            &user_pub_key,
            &cipher0,
            &cipher1,
            &auditor_pub_key,
            None,
        )
        .expect("verification should succeed");

        assert!(is_valid, "proof should be valid");
    }

    #[test]
    fn test_audit_invalid_balance() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create cipher0 with WRONG balance
        let wrong_balance = 999u128;
        let r0 = Felt::from(98765u64);
        let g_b_wrong = StarkCurve::mul(&Felt::from(wrong_balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b_wrong, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        let auditor_private = Felt::from(99999u64);
        let auditor_pub_key = StarkCurve::mul(&auditor_private, Some(&g));

        // This should fail because cipher0 doesn't match the balance we claim
        let result = AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None);
        assert!(result.is_err(), "proof should fail with invalid cipher0");
    }

    /// Test vector from TypeScript: typescript-reference/tongo-sdk/test/unit/audit.test.ts
    /// This MUST produce identical outputs to TypeScript for cross-implementation validation.
    #[test]
    fn test_audit_typescript_test_vector() {
        println!("\n=== TypeScript Test Vector: Audit Prover ===\n");

        // Exact values from audit.test.ts
        let private_key = Felt::from(290820943832u64);
        let auditor_private_key = Felt::from(109283109831u64);
        let initial_balance = 300u128;
        let r = Felt::from(89327498324u64);

        let g = StarkCurve::generator();

        // Compute public keys
        let public_key = StarkCurve::mul_generator(&private_key);
        let auditor_public_key = StarkCurve::mul_generator(&auditor_private_key);

        println!("📥 Inputs:");
        println!("  private_key: {}", private_key);
        println!("  public_key:");
        let pk_affine = public_key.to_affine().unwrap();
        println!("    x: {:#x}", pk_affine.x());
        println!("    y: {:#x}", pk_affine.y());
        println!("  auditor_private_key: {}", auditor_private_key);
        println!("  auditor_public_key:");
        let apk_affine = auditor_public_key.to_affine().unwrap();
        println!("    x: {:#x}", apk_affine.x());
        println!("    y: {:#x}", apk_affine.y());
        println!("  initial_balance: {}", initial_balance);
        println!("  random (r): {}", r);

        // Create cipher balance: createCipherBalance(public_key, initial_balance, r)
        // L = g^balance + public_key^r
        // R = g^r
        let g_b = StarkCurve::mul(&Felt::from(initial_balance), Some(&g));
        let y_r = StarkCurve::mul(&r, Some(&public_key));
        let l = StarkCurve::add(&g_b, &y_r);
        let r_point = StarkCurve::mul(&r, Some(&g));

        let initial_cipher_balance = ElGamalCiphertext {
            l: l.clone(),
            r: r_point.clone(),
        };

        println!("\n  initial_cipher_balance:");
        let l_affine = l.to_affine().unwrap();
        let r_affine = r_point.to_affine().unwrap();
        println!("    L:");
        println!("      x: {:#x}", l_affine.x());
        println!("      y: {:#x}", l_affine.y());
        println!("    R:");
        println!("      x: {:#x}", r_affine.x());
        println!("      y: {:#x}", r_affine.y());

        // Generate proof
        let (proof, audited_balance) = AuditProver::prove(
            &private_key,
            initial_balance,
            &initial_cipher_balance,
            &auditor_public_key,
            None,
        )
        .expect("proof generation should succeed");

        println!("\n📤 Outputs:");
        println!("\n  Proof:");
        println!("    Ax:");
        println!("      x: {}", proof.ax.x);
        println!("      y: {}", proof.ax.y);
        println!("    AL0:");
        println!("      x: {}", proof.al0.x);
        println!("      y: {}", proof.al0.y);
        println!("    AL1:");
        println!("      x: {}", proof.al1.x);
        println!("      y: {}", proof.al1.y);
        println!("    AR1:");
        println!("      x: {}", proof.ar1.x);
        println!("      y: {}", proof.ar1.y);
        println!("    sx: {}", proof.sx);
        println!("    sb: {}", proof.sb);
        println!("    sr: {}", proof.sr);
        println!("    c: {}", proof.c);

        println!("\n  Audited Balance:");
        let ab_l_affine = audited_balance.l.to_affine().unwrap();
        let ab_r_affine = audited_balance.r.to_affine().unwrap();
        println!("    L:");
        println!("      x: {:#x}", ab_l_affine.x());
        println!("      y: {:#x}", ab_l_affine.y());
        println!("    R:");
        println!("      x: {:#x}", ab_r_affine.x());
        println!("      y: {:#x}", ab_r_affine.y());

        // Verify proof
        let is_valid = AuditProver::verify(
            &proof,
            &public_key,
            &initial_cipher_balance,
            &audited_balance,
            &auditor_public_key,
            None,
        )
        .expect("verification should succeed");

        println!(
            "\n✅ Verification: {}",
            if is_valid { "PASSED" } else { "FAILED" }
        );
        assert!(is_valid, "proof should be valid");

        println!("\n=== End Test Vector ===\n");
    }

    #[test]
    fn test_audit_zero_balance() {
        // Test the special case for balance = 0
        let private_key = Felt::from(12345u64);
        let balance = 0u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create cipher0 with zero balance
        let r0 = Felt::from(98765u64);
        // For balance=0: L = 0*g + pk*r = pk*r (since 0*g = identity)
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = user_r0; // L = pk*r0 when balance is 0
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        let auditor_private = Felt::from(99999u64);
        let auditor_pub_key = StarkCurve::mul(&auditor_private, Some(&g));

        // Generate proof with validation disabled (since cipher0 format differs for zero balance)
        let result = AuditProver::prove_with_validation(
            &private_key,
            balance,
            &cipher0,
            &auditor_pub_key,
            false,
            None,
        );
        assert!(
            result.is_ok(),
            "proof should succeed for zero balance with validation disabled"
        );

        let (proof, cipher1) = result.unwrap();

        // Verify proof
        let is_valid = AuditProver::verify(
            &proof,
            &user_pub_key,
            &cipher0,
            &cipher1,
            &auditor_pub_key,
            None,
        )
        .expect("verification should succeed");
        assert!(is_valid, "proof should be valid for zero balance");
    }

    #[test]
    fn test_audit_cipher0_l_infinity() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        // Create cipher0 with L at infinity
        let cipher0 = ElGamalCiphertext {
            l: ProjectivePoint::identity(),
            r: StarkCurve::mul_generator(&Felt::from(98765u64)),
        };

        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(99999u64));

        let result = AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("cipher0.l is point at infinity"));
        }
    }

    #[test]
    fn test_audit_cipher0_r_infinity() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        // Create cipher0 with R at infinity
        let cipher0 = ElGamalCiphertext {
            l: StarkCurve::mul_generator(&Felt::from(123u64)),
            r: ProjectivePoint::identity(),
        };

        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(99999u64));

        let result = AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("cipher0.r is point at infinity"));
        }
    }

    #[test]
    fn test_audit_auditor_pub_key_infinity() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create valid cipher0
        let r0 = Felt::from(98765u64);
        let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        // Use infinity as auditor public key
        let auditor_pub_key = ProjectivePoint::identity();

        let result = AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None);
        assert!(result.is_err());
        if let Err(krusty_kms_common::KmsError::CryptoError(msg)) = result {
            assert!(msg.contains("auditor_pub_key is point at infinity"));
        }
    }

    #[test]
    fn test_audit_prove_with_validation_disabled() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create a cipher0 that doesn't match the balance (would fail validation)
        let wrong_balance = 999u128;
        let r0 = Felt::from(98765u64);
        let g_b_wrong = StarkCurve::mul(&Felt::from(wrong_balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b_wrong, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(99999u64));

        // With validation enabled, this should fail
        let result_with_validation = AuditProver::prove_with_validation(
            &private_key,
            balance,
            &cipher0,
            &auditor_pub_key,
            true,
            None,
        );
        assert!(result_with_validation.is_err());

        // With validation disabled, this should succeed (even though proof won't verify correctly)
        let result_without_validation = AuditProver::prove_with_validation(
            &private_key,
            balance,
            &cipher0,
            &auditor_pub_key,
            false,
            None,
        );
        assert!(result_without_validation.is_ok());
    }

    #[test]
    fn test_audit_verify_invalid_challenge() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        // Create valid cipher0
        let r0 = Felt::from(98765u64);
        let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(99999u64));

        let (mut proof, cipher1) =
            AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None)
                .expect("proof generation should succeed");

        // Tamper with challenge
        proof.c = Felt::from(999999u64);

        let is_valid = AuditProver::verify(
            &proof,
            &user_pub_key,
            &cipher0,
            &cipher1,
            &auditor_pub_key,
            None,
        )
        .expect("verification should succeed");
        assert!(!is_valid, "proof with tampered challenge should be invalid");
    }

    #[test]
    fn test_audit_verify_invalid_sx() {
        let private_key = Felt::from(12345u64);
        let balance = 1000u128;

        let g = StarkCurve::generator();
        let user_pub_key = StarkCurve::mul(&private_key, Some(&g));

        let r0 = Felt::from(98765u64);
        let g_b = StarkCurve::mul(&Felt::from(balance), Some(&g));
        let user_r0 = StarkCurve::mul(&r0, Some(&user_pub_key));
        let l0 = StarkCurve::add(&g_b, &user_r0);
        let r0_point = StarkCurve::mul(&r0, Some(&g));
        let cipher0 = ElGamalCiphertext { l: l0, r: r0_point };

        let auditor_pub_key = StarkCurve::mul_generator(&Felt::from(99999u64));

        let (mut proof, cipher1) =
            AuditProver::prove(&private_key, balance, &cipher0, &auditor_pub_key, None)
                .expect("proof generation should succeed");

        // Tamper with sx (but keep challenge valid to test equation 1)
        proof.sx = Felt::from(1u64);

        let is_valid = AuditProver::verify(
            &proof,
            &user_pub_key,
            &cipher0,
            &cipher1,
            &auditor_pub_key,
            None,
        )
        .expect("verification should succeed");
        assert!(!is_valid, "proof with tampered sx should be invalid");
    }
}
