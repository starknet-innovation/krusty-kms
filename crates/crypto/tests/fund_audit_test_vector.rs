//! Fund + Audit Test Vector Generator
//!
//! Generates a complete fund operation with audit using the exact same inputs
//! as TypeScript reference tests, allowing for direct comparison.

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_crypto::{
    audit::AuditProver, hash::compute_poseidon_challenge, poe::ProofOfExponentiation,
    poseidon_hash_many, StarkCurve,
};
use starknet_types_core::felt::Felt;

/// Cairo string 'fund' = 1718972004
const FUND_CAIRO_STRING: u64 = 1718972004;

/// Cairo string 'audit' = 418581342580
const AUDIT_CAIRO_STRING: u64 = 418581342580;

#[test]
fn test_fund_with_audit_typescript_vector() {
    println!("\n=== Rust Test Vector: Fund + Audit ===\n");

    // ===== INPUTS (matching TypeScript fund.test.ts) =====
    let private_key = Felt::from(290820943832u64);
    let initial_balance = 30u128;
    let r = Felt::from(31092830921839021u128);
    let amount_to_fund = 100u128;
    let nonce = Felt::from(1u64);
    let chain_id = Felt::from(1111u64);
    let tongo_address = Felt::from(22222u64);

    // Auditor setup
    let auditor_private_key = Felt::from(109283109831u64);

    let g = StarkCurve::generator();
    let public_key = StarkCurve::mul(&private_key, Some(&g));
    let auditor_public_key = StarkCurve::mul(&auditor_private_key, Some(&g));

    println!("📥 Inputs:");
    println!("  private_key: {}", private_key);
    let pk_affine = public_key.to_affine().unwrap();
    println!("  public_key:");
    println!("    x: {:#x}", pk_affine.x());
    println!("    y: {:#x}", pk_affine.y());
    println!("  auditor_private_key: {}", auditor_private_key);
    let apk_affine = auditor_public_key.to_affine().unwrap();
    println!("  auditor_public_key:");
    println!("    x: {:#x}", apk_affine.x());
    println!("    y: {:#x}", apk_affine.y());
    println!("  initial_balance: {}", initial_balance);
    println!("  random (r): {}", r);
    println!("  amount_to_fund: {}", amount_to_fund);
    println!("  nonce: {}", nonce);
    println!("  chain_id: {}", chain_id);
    println!("  tongo_address: {}", tongo_address);

    // ===== CREATE INITIAL CIPHER BALANCE =====
    // TypeScript: createCipherBalance(public_key, initial_balance, _r)
    // L = g^balance + y^r, R = g^r
    let initial_cipher_balance = create_cipher_balance(&public_key, initial_balance, &r);

    println!("\n  initial_cipher_balance:");
    let l_affine = initial_cipher_balance.l.to_affine().unwrap();
    let r_affine = initial_cipher_balance.r.to_affine().unwrap();
    println!("    L:");
    println!("      x: {:#x}", l_affine.x());
    println!("      y: {:#x}", l_affine.y());
    println!("    R:");
    println!("      x: {:#x}", r_affine.x());
    println!("      y: {:#x}", r_affine.y());

    // Verify initial cipher balance is correct encryption
    let r_x = StarkCurve::mul(&private_key, Some(&initial_cipher_balance.r));
    let g_b_actual = &initial_cipher_balance.l - &r_x;
    let g_b_expected = StarkCurve::mul(&Felt::from(initial_balance), Some(&g));
    assert_eq!(
        g_b_actual, g_b_expected,
        "Initial cipher balance verification failed"
    );
    println!("  ✓ Initial cipher balance verified");

    // ===== FUND PROOF GENERATION =====
    println!("\n📤 Fund Proof Generation:");

    // Compute prefix
    let y_affine = public_key.to_affine().unwrap();
    let prefix_inputs = vec![
        chain_id,
        tongo_address,
        Felt::from(FUND_CAIRO_STRING),
        y_affine.x(),
        y_affine.y(),
        Felt::from(amount_to_fund),
        nonce,
    ];
    let prefix = poseidon_hash_many(&prefix_inputs);
    println!("  prefix: {:#x}", prefix);

    // Generate PoE proof (proves knowledge of private key)
    let (_, fund_proof) = ProofOfExponentiation::prove(&private_key, &prefix).unwrap();

    println!("  Fund Proof:");
    println!("    Ax: (x: {}, y: {})", fund_proof.a.x, fund_proof.a.y);
    println!("    sx: {}", fund_proof.s);

    // ===== AUDIT PROOF GENERATION =====
    println!("\n📤 Audit Proof Generation:");

    let (audit_proof, audited_balance) = AuditProver::prove(
        &private_key,
        initial_balance,
        &initial_cipher_balance,
        &auditor_public_key,
        None,
    )
    .unwrap();

    println!("  Audit Proof:");
    println!("    Ax: (x: {}, y: {})", audit_proof.ax.x, audit_proof.ax.y);
    println!(
        "    AL0: (x: {}, y: {})",
        audit_proof.al0.x, audit_proof.al0.y
    );
    println!(
        "    AL1: (x: {}, y: {})",
        audit_proof.al1.x, audit_proof.al1.y
    );
    println!(
        "    AR1: (x: {}, y: {})",
        audit_proof.ar1.x, audit_proof.ar1.y
    );
    println!("    sx: {}", audit_proof.sx);
    println!("    sb: {}", audit_proof.sb);
    println!("    sr: {}", audit_proof.sr);
    println!("    c: {}", audit_proof.c);

    // Manually verify challenge computation
    println!("\n  Challenge Computation Verification:");
    let audit_prefix = Felt::from(AUDIT_CAIRO_STRING);
    println!("    prefix (AUDIT_CAIRO_STRING): {:#x}", audit_prefix);

    // Reconstruct points from serialized proof
    let ax_rec = krusty_kms_common::SerializablePoint {
        x: audit_proof.ax.x,
        y: audit_proof.ax.y,
    }
    .to_affine()
    .unwrap()
    .try_into()
    .unwrap();
    let al0_rec: starknet_types_core::curve::ProjectivePoint =
        krusty_kms_common::SerializablePoint {
            x: audit_proof.al0.x,
            y: audit_proof.al0.y,
        }
        .to_affine()
        .unwrap()
        .try_into()
        .unwrap();
    let al1_rec: starknet_types_core::curve::ProjectivePoint =
        krusty_kms_common::SerializablePoint {
            x: audit_proof.al1.x,
            y: audit_proof.al1.y,
        }
        .to_affine()
        .unwrap()
        .try_into()
        .unwrap();
    let ar1_rec: starknet_types_core::curve::ProjectivePoint =
        krusty_kms_common::SerializablePoint {
            x: audit_proof.ar1.x,
            y: audit_proof.ar1.y,
        }
        .to_affine()
        .unwrap()
        .try_into()
        .unwrap();

    let c_recomputed =
        compute_poseidon_challenge(&audit_prefix, &[&ax_rec, &al0_rec, &al1_rec, &ar1_rec])
            .unwrap();
    println!("    recomputed c: {:#x}", c_recomputed);
    println!("    c from proof: {}", audit_proof.c);
    assert_eq!(c_recomputed, audit_proof.c, "Challenge mismatch!");

    println!("\n  Audited Balance:");
    let ab_l_affine = audited_balance.l.to_affine().unwrap();
    let ab_r_affine = audited_balance.r.to_affine().unwrap();
    println!("    L:");
    println!("      x: {:#x}", ab_l_affine.x());
    println!("      y: {:#x}", ab_l_affine.y());
    println!("    R:");
    println!("      x: {:#x}", ab_r_affine.x());
    println!("      y: {:#x}", ab_r_affine.y());

    // ===== VERIFICATION =====
    println!("\n🔍 Verification:");

    // Verify fund proof - manually reconstruct from serialized format
    let fund_a_affine = krusty_kms_common::SerializablePoint {
        x: fund_proof.a.x,
        y: fund_proof.a.y,
    }
    .to_affine()
    .unwrap();
    let fund_a_point: starknet_types_core::curve::ProjectivePoint =
        fund_a_affine.try_into().unwrap();
    let fund_s_felt = fund_proof.s;

    let fund_prefix_for_verification = poseidon_hash_many(&prefix_inputs);
    let fund_challenge =
        compute_poseidon_challenge(&fund_prefix_for_verification, &[&fund_a_point]).unwrap();
    let g_sx = StarkCurve::mul(&fund_s_felt, Some(&g));
    let y_c = StarkCurve::mul(&fund_challenge, Some(&public_key));
    let rhs_fund = StarkCurve::add(&fund_a_point, &y_c);
    assert_eq!(
        g_sx, rhs_fund,
        "Fund proof verification failed: g^sx != Ax + y^c"
    );
    println!("  ✓ Fund proof verified");

    // Verify audit proof
    let is_valid = AuditProver::verify(
        &audit_proof,
        &public_key,
        &initial_cipher_balance,
        &audited_balance,
        &auditor_public_key,
        None,
    )
    .unwrap();
    assert!(is_valid, "Audit proof verification failed");
    println!("  ✓ Audit proof verified");

    println!("\n=== End Test Vector ===\n");
}

/// Create an ElGamal ciphertext matching TypeScript's createCipherBalance.
///
/// TypeScript code:
/// ```ts
/// const L = GENERATOR.multiply(amount).add(y.multiplyUnsafe(random));
/// const R = GENERATOR.multiplyUnsafe(random);
/// return { L, R };
/// ```
fn create_cipher_balance(
    public_key: &starknet_types_core::curve::ProjectivePoint,
    amount: u128,
    random: &Felt,
) -> ElGamalCiphertext {
    let g = StarkCurve::generator();

    if amount == 0 {
        // Special case for zero amount
        let l = StarkCurve::mul(random, Some(public_key));
        let r = StarkCurve::mul(random, Some(&g));
        return ElGamalCiphertext { l, r };
    }

    // L = g^amount + y^random
    let g_amount = StarkCurve::mul(&Felt::from(amount), Some(&g));
    let y_random = StarkCurve::mul(random, Some(public_key));
    let l = StarkCurve::add(&g_amount, &y_random);

    // R = g^random
    let r = StarkCurve::mul(random, Some(&g));

    ElGamalCiphertext { l, r }
}
